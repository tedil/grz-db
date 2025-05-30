import datetime
import enum
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from pydantic import BaseModel
from sqlalchemy import JSON, Column
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select


class CaseInsensitiveStrEnum(enum.StrEnum):
    """
    A StrEnum that is case-insensitive for member lookup and comparison with strings.
    """

    @classmethod
    def _missing_(cls, value):
        """
        Override to allow case-insensitive lookup of enum members by value.
        e.g., MyEnum('value') will match MyEnum.VALUE.
        """
        if isinstance(value, str):
            for member in cls:
                if member.value.casefold() == value.casefold():
                    return member
        return None

    def __eq__(self, other):
        """
        Override to allow case-insensitive comparison of enum members by value.
        """
        if isinstance(other, enum.Enum):
            return self is other
        if isinstance(other, str):
            return self.value.casefold() == other.casefold()
        return NotImplemented

    def __hash__(self):
        """
        Override to make hash consistent with eq.
        """
        return hash(self.value.casefold())


class SubmissionStateEnum(CaseInsensitiveStrEnum):
    """Submission state enum."""

    UPLOADING = "Uploading"
    UPLOADED = "Uploaded"
    DOWNLOADING = "Downloading"
    DOWNLOADED = "Downloaded"
    DECRYPTING = "Decrypting"
    DECRYPTED = "Decrypted"
    VALIDATING = "Validating"
    VALIDATED = "Validated"
    ENCRYPTING = "Encrypting"
    ENCRYPTED = "Encrypted"
    ARCHIVING = "Archiving"
    ARCHIVED = "Archived"
    REPORTED = "Reported"
    QCING = "QCing"
    QCED = "QCed"
    CLEANING = "Cleaning"
    CLEANED = "Cleaned"
    FINISHED = "Finished"
    ERROR = "Error"


class SubmissionBase(SQLModel):
    """Submission base model."""

    tan_g: str | None = Field(default=None, unique=True, index=True, alias="tanG")
    pseudonym: str | None = Field(default=None, index=True)


class Submission(SubmissionBase, table=True):
    """Submission table model."""

    __tablename__ = "submissions"

    id: str = Field(primary_key=True, index=True)

    states: list["SubmissionStateLog"] = Relationship(back_populates="submission")


class SubmissionStateLogBase(SQLModel):
    """
    Submission state log base model.
    Holds state information for each submission.
    Timestamped.
    Can optionally have associated JSON data.
    """

    state: SubmissionStateEnum
    data: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC), nullable=False)


class SubmissionStateLogPayload(SubmissionStateLogBase):
    """
    Used to bundle data for signature calculation.
    """

    submission_id: str
    author_name: str

    def to_bytes(self) -> bytes:
        """A representation of submission state."""
        return self.model_dump_json(by_alias=True).encode("utf8")


class SubmissionStateLog(SubmissionStateLogBase, table=True):
    """Submission state log table model."""

    __tablename__ = "submission_states"

    id: int | None = Field(default=None, primary_key=True, index=True)
    submission_id: str = Field(foreign_key="submissions.id", index=True)

    author_name: str = Field(index=True)
    signature: str

    submission: Submission | None = Relationship(back_populates="states")


class SubmissionStateLogCreate(SubmissionStateLogBase):
    """Submission state log create model."""

    submission_id: str
    author_name: str
    signature: str


class SubmissionCreate(SubmissionBase):
    """Submission create model."""

    id: str


class SubmissionNotFoundError(ValueError):
    """Exception for when a submission is not found in the database."""

    def __init__(self, submission_id: str):
        super().__init__(f"Submission not found for ID {submission_id}")


class DuplicateSubmissionError(ValueError):
    """Exception for when a submission ID already exists in the database."""

    def __init__(self, submission_id: str):
        super().__init__(f"Duplicate submission ID {submission_id}")


class DuplicateTanGError(ValueError):
    """Exception for when a tanG is already in use."""

    def __init__(self, tan_g: str):
        super().__init__(f"Duplicate tanG {tan_g}")


class DatabaseConfigurationError(Exception):
    """Exception for database configuration issues."""

    pass


class Author:
    def __init__(self, name: str, private_key: PrivateKeyTypes):
        self.name = name
        self.private_key = private_key


class SubmissionDb:
    """
    API entrypoint for managing submissions.
    """

    def __init__(self, db_url: str, author: Author | None, debug: bool = False):
        """
        Initializes the SubmissionDb.

        Args:
            db_url: Database URL.
            debug: Whether to echo SQL statements.
        """
        self.engine = create_engine(db_url, echo=debug)
        self._author = author

    @contextmanager
    def get_session(self) -> Generator[Session, Any, None]:
        """Get an sqlmodel session."""
        with Session(self.engine) as session:
            yield session

    def _get_alembic_config(self, alembic_ini_path: str) -> AlembicConfig:
        """
        Loads the alembic configuration.

        Args:
            alembic_ini_path: Path to alembic ini file.
        """
        if not alembic_ini_path or not os.path.exists(alembic_ini_path):
            raise ValueError(f"Alembic configuration file not found at: {alembic_ini_path}")

        alembic_cfg = AlembicConfig(alembic_ini_path)
        alembic_cfg.set_main_option("sqlalchemy.url", str(self.engine.url))
        alembic_cfg.set_main_option("script_location", "grz_db:migrations")
        return alembic_cfg

    def initialize_schema(self):
        """Initialize the database."""
        SQLModel.metadata.create_all(self.engine, checkfirst=True)

    def upgrade_schema(self, alembic_ini_path: str, revision: str = "head"):
        """
        Upgrades the database schema using alembic.

        Args:
            alembic_ini_path: Path to the alembic.ini file.
            revision: The Alembic revision to upgrade to (default: 'head').

        Raises:
            RuntimeError: For underlying Alembic errors.
        """
        alembic_cfg = self._get_alembic_config(alembic_ini_path)
        try:
            alembic_command.upgrade(alembic_cfg, revision)
        except Exception as e:
            raise RuntimeError(f"Alembic upgrade failed: {e}") from e

    def add_submission(
        self,
        submission_id: str,
        tan_g: str | None = None,
        pseudonym: str | None = None,
    ) -> Submission:
        """
        Adds a submission to the database.

        Args:
            submission_id: Submission ID.
            tan_g: tanG if in phase 0
            pseudonym: pseudonym if phase >= 0

        Returns:
            An instance of Submission.
        """
        with self.get_session() as session:
            existing_submission = session.get(Submission, submission_id)
            if existing_submission:
                raise DuplicateSubmissionError(submission_id)

            submission_create = SubmissionCreate(id=submission_id, tan_g=tan_g, pseudonym=pseudonym)
            db_submission = Submission.model_validate(submission_create)

            session.add(db_submission)
            try:
                session.commit()
                session.refresh(db_submission)
                return db_submission
            except IntegrityError as e:
                session.rollback()
                if "UNIQUE constraint failed: submissions.tanG" in str(e) and tan_g:
                    raise DuplicateTanGError(tan_g) from e
                raise
            except Exception:
                session.rollback()
                raise

    def update_submission_state(
        self,
        submission_id: str,
        state: SubmissionStateEnum,
        data: dict | None = None,
    ) -> SubmissionStateLog:
        """
        Updates a submission's state to the specified state.

        Args:
            submission_id: Submission ID of the submission to update.
            state: New state of the submission.
            data: Optional data to attach to the update.

        Returns:
            An instance of SubmissionStateLog.
        """
        with self.get_session() as session:
            submission = session.get(Submission, submission_id)
            if not submission:
                raise SubmissionNotFoundError(submission_id)

            state_log_payload = SubmissionStateLogPayload(
                submission_id=submission_id, author_name=self._author.name, state=state, data=data
            )
            bytes_to_sign = state_log_payload.to_bytes()
            signature = self._author.private_key.sign(bytes_to_sign)

            state_log_create = SubmissionStateLogCreate(**state_log_payload.model_dump(), signature=signature.hex())
            db_state_log = SubmissionStateLog.model_validate(state_log_create)
            session.add(db_state_log)

            # Remove tanG once it has been reported?
            if state == SubmissionStateEnum.REPORTED and submission.tan_g is not None:
                submission.tan_g = None
                session.add(submission)

            try:
                session.commit()
                session.refresh(db_state_log)
                if state == SubmissionStateEnum.REPORTED and submission.tan_g is None:
                    session.refresh(submission)
                return db_state_log
            except Exception:
                session.rollback()
                raise

    def get_submission(self, submission_id: str) -> Submission | None:
        """
        Retrieves a submission and its state history.

        Args:
            submission_id: Submission ID of the submission to retrieve.

        Returns:
            An instance of Submission or None.
        """
        with self.get_session() as session:
            statement = (
                select(Submission).where(Submission.id == submission_id).options(selectinload(Submission.states))
            )
            submission = session.exec(statement).first()
            return submission

    def list_submissions(self) -> list[Submission]:
        """
        Lists all submissions in the database.

        Returns:
            A list of all submissions in the database, ordered by their ID.
        """
        with self.get_session() as session:
            statement = select(Submission).options(selectinload(Submission.states)).order_by(Submission.id)
            submissions = session.exec(statement).all()
            return submissions
