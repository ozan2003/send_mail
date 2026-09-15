#!/usr/bin/env python3
"""Send application emails with a CV attached through SMTP."""

import argparse
import itertools
import logging
import mimetypes
import re
import smtplib
import sys
import textwrap
import tomllib
from email.message import EmailMessage
from email.utils import localtime, make_msgid
from logging import getLevelName
from pathlib import Path
from random import uniform
from time import sleep
from typing import (
    TYPE_CHECKING,
    Any,
    Final,
    NamedTuple,
    NewType,
    NoReturn,
    NotRequired,
    TypedDict,
    cast,
    override,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
# SMTP credential types.
Sender = NewType("Sender", str)
Password = NewType("Password", str)
Host = NewType("Host", str)
Port = NewType("Port", int)


class EmailConfig(TypedDict):
    """Schema for config.toml."""

    subject: str
    message: str
    attachment_path: NotRequired[str]


# Project identity for the User-Agent header of the emails.
PROJECT_NAME: Final = "send-mail"
PROJECT_VERSION: Final = "0.1.0"

# Default configuration directory in the user home directory.
DEFAULT_CONFIG_DIR: Final = Path.home() / ".config" / "send_cv"
CONFIG_FILENAME: Final = "config.toml"
CREDENTIALS_FILENAME: Final = "credentials.toml"
DEFAULT_CONFIG_PATH: Final = DEFAULT_CONFIG_DIR / CONFIG_FILENAME
DEFAULT_CREDENTIALS_PATH: Final = DEFAULT_CONFIG_DIR / CREDENTIALS_FILENAME

# Default location of the sent log. The log records the recipients that
# received an email, so a later run does not email them again.
DEFAULT_SENT_LOG_PATH: Final = (
    Path(__file__).resolve().parent / "sent_emails.log"
)

# Defaults of the command-line options.
DEFAULT_BATCH_SIZE: Final = 3
DEFAULT_LOG_LEVEL: Final = "info"
LOG_LEVELS: Final = ("debug", "info", "warning", "error", "critical")

# Default host and port of the SMTP server.
DEFAULT_SMTP_HOST: Final = Host("smtp.gmail.com")
DEFAULT_SMTP_PORT: Final = Port(465)

# Mail sending parameters.
# Socket timeout for each operation on the SMTP connection, in seconds.
SMTP_TIMEOUT: Final = 30.0
# Shortest and longest wait between two emails, in seconds.
WAIT_TIMES: Final = (3.0, 9.0)
ATTEMPT_LIMIT: Final = 5  # Maximum number of attempts for one email.

# SMTP response codes that defer a message. The server did not accept the
# message, so a retry cannot deliver it twice.
TEMPORARY_SMTP_CODES: Final = frozenset({421, 450, 451, 452})

# Address format accepted for senders and recipients.
EMAIL_PATTERN: Final = re.compile(
    r"(^[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}$)"
)

# Templates for the starter files.
CREDENTIALS_TEMPLATE = f"""# SMTP credentials for the email account.
[smtp]
sender = "your.email@gmail.com"
# For Gmail, use an App Password. Get one at https://myaccount.google.com/apppasswords
password = "your-app-password"
host = "{DEFAULT_SMTP_HOST}"
port = {DEFAULT_SMTP_PORT}
"""

CONFIG_TEMPLATE = """# Message template for the emails.
subject = "Application for Position"

# Absolute path to the CV file, for example "~/Documents/cv.pdf" or "C:/Users/.../cv.pdf"
attachment_path = "~/Documents/cv.pdf"

message = \"\"\"
Dear Hiring Team,

Please find attached my CV for your consideration.

Best regards,
\"\"\"
"""

# Logger for this module.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Utilities: file input and the sent log
# ---------------------------------------------------------------------------
def load_file(file_path: Path) -> tuple[str, bytes]:
    """Read a file and return its name and its data.

    Args:
        file_path (Path): Path to the file.

    Returns:
        tuple[str, bytes]: The file name and the file data.

    Raises:
        FileNotFoundError: The file does not exist.
        OSError: The file cannot be read.
    """
    if not file_path.exists():
        msg = f"File not found at {file_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    try:
        with file_path.open("rb") as fp:
            file_data = fp.read()
            file_name = file_path.name
            logger.debug("Read the file %s", file_name)
    except OSError as exc:
        msg = f"Failed to read the file: {exc}"
        raise OSError(msg) from exc

    return file_name, file_data


def parse_toml(toml_path: Path) -> dict[str, Any]:
    """Read a TOML file and return its data.

    Args:
        toml_path (Path): Path to the TOML file.

    Returns:
        dict[str, Any]: The data from the TOML file.

    Raises:
        OSError: The file cannot be read.
        ValueError: The TOML syntax is not correct.
    """
    try:
        with Path.open(toml_path, "rb") as f:
            data = tomllib.load(f)
            logger.debug("Read the configuration file")
    except tomllib.TOMLDecodeError as exc:
        msg = f"The TOML syntax in {toml_path} is not correct: {exc}"
        raise ValueError(msg) from exc
    except OSError as exc:
        msg = f"Failed to read the configuration file: {exc}"
        raise OSError(msg) from exc

    return data


def _read_email_file(path: Path) -> tuple[list[str], int]:
    """Read one address file and return its addresses.

    Args:
        path (Path): Path to the file with the email addresses.

    Returns:
        tuple[list[str], int]: The correct addresses, and the number of lines
            that do not have the address format.

    Raises:
        FileNotFoundError: The file does not exist.
        OSError: The file cannot be read.
    """
    if not path.exists():
        msg = f"Email file not found at {path}"
        raise FileNotFoundError(msg)
    logger.debug("Email file: %s", path)

    valid_emails: list[str] = []
    invalid_count = 0
    with path.open("r", encoding="utf-8") as fp:
        for line_num, line in enumerate(fp, start=1):
            email = line.strip()
            if len(email) == 0:
                continue  # Ignore empty lines.

            if EMAIL_PATTERN.match(email):
                valid_emails.append(email)
            else:
                invalid_count += 1
                logger.warning(
                    "Email address '%s' is not correct in file %s, line %d",
                    email,
                    path,
                    line_num,
                )

    if invalid_count > 0:
        logger.info(
            "Skipped %d email addresses that are not correct in %s",
            invalid_count,
            path,
        )

    return valid_emails, invalid_count


def load_emails_from_files(file_paths: Iterable[Path]) -> list[str]:
    """Read email addresses from one or more files.

    The function skips the addresses that are not correct. It logs the file
    name and the line number of each one.

    Args:
        file_paths (Iterable[Path]): Paths to the files with the addresses.

    Returns:
        list[str]: The addresses that are correct.

    Raises:
        FileNotFoundError: A file does not exist.
        OSError: A file cannot be read.
    """
    valid_emails: list[str] = []
    total_invalid_count = 0
    try:
        for path in file_paths:
            file_emails, invalid_count = _read_email_file(path)
            valid_emails.extend(file_emails)
            total_invalid_count += invalid_count
    except FileNotFoundError:
        raise
    except OSError as exc:
        msg = f"Failed to read an email file: {exc}"
        raise OSError(msg) from exc
    else:
        if total_invalid_count > 0:
            logger.info(
                "Skipped %d email addresses that are not correct in all files",
                total_invalid_count,
            )

        return valid_emails


def deduplicate_emails(receivers: Iterable[str]) -> tuple[list[str], int]:
    """Remove duplicate addresses and keep the first occurrence.

    The comparison ignores uppercase and lowercase letters.

    Args:
        receivers (Iterable[str]): The email addresses.

    Returns:
        tuple[list[str], int]: The addresses without duplicates, and the
            number of duplicates.
    """
    seen: set[str] = set()
    unique: list[str] = []
    duplicate_count = 0

    for email in receivers:
        normalized = email.strip().lower()
        if not normalized:
            continue
        if normalized in seen:
            duplicate_count += 1
            logger.debug("Ignored the duplicate address %s", email)
            continue
        seen.add(normalized)
        unique.append(email)

    return unique, duplicate_count


def load_sent_log(log_path: Path) -> set[str]:
    """Read the sent log and return the addresses in it.

    The function returns an empty set if the log file does not exist.

    Args:
        log_path (Path): Path to the sent log.

    Returns:
        set[str]: The addresses in the log, in lowercase and without spaces.
    """
    if not log_path.exists():
        return set()

    sent: set[str] = set()
    try:
        with log_path.open("r", encoding="utf-8") as fp:
            for raw_line in fp:
                entry = raw_line.strip()
                if not entry or entry.startswith("#"):
                    continue
                sent.add(entry.split()[0].lower())
    except OSError as exc:
        logger.warning(
            "Cannot read the sent log at %s (%s). The script does not skip "
            "any recipients",
            log_path,
            exc,
        )
        return set()

    return sent


def append_to_sent_log(log_path: Path, recipients: Iterable[str]) -> None:
    """Add recipient addresses and the current time to the sent log.

    Args:
        log_path (Path): Path to the log file.
        recipients (Iterable[str]): The addresses that the server accepted.
    """
    now = localtime().strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fp:
            for recipient in recipients:
                fp.write(f"{recipient.strip()} {now}\n")
    except OSError as exc:
        logger.warning(
            "Failed to write the recipients %s to the sent log %s: %s",
            recipients,
            log_path,
            exc,
        )


def filter_unsent(
    receivers: Iterable[str],
    sent_recipients: set[str],
) -> tuple[list[str], int]:
    """Remove the recipients that are already in the sent log.

    Args:
        receivers (Iterable[str]): The candidate email addresses.
        sent_recipients (set[str]): The addresses from the sent log.

    Returns:
        tuple[list[str], int]: The recipients that remain, and the number that
            the function removed.
    """
    unsent: list[str] = []
    skipped_count = 0

    for email in receivers:
        normalized = email.strip().lower()
        if normalized in sent_recipients:
            skipped_count += 1
            logger.debug(
                "Already in the sent log: %s",
                email,
            )
        else:
            unsent.append(email)

    return unsent, skipped_count


# ---------------------------------------------------------------------------
# Configuration and command line
# ---------------------------------------------------------------------------
def ensure_config_scaffold(config_dir: Path) -> None:
    """Create the configuration directory and the starter files.

    The function does nothing if the files exist.

    Args:
        config_dir (Path): Configuration directory to create.
    """
    config_dir.mkdir(parents=True, exist_ok=True)

    credentials_file = config_dir / CREDENTIALS_FILENAME
    if not credentials_file.exists():
        credentials_file.write_text(CREDENTIALS_TEMPLATE, encoding="utf-8")
        # The file will hold the password, so only the owner may read it.
        # On Windows, chmod changes only the read-only flag, and the user
        # profile already limits access to the file.
        credentials_file.chmod(0o600)
        logger.info("Created the credentials file at %s", credentials_file)

    config_file = config_dir / CONFIG_FILENAME
    if not config_file.exists():
        config_file.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        logger.info("Created the configuration file at %s", config_file)


def resolve_config_path(
    explicit_path: str | None,
    filename: str,
    default_path: Path,
) -> Path:
    """Find the configuration file and return its path.

    The search uses this sequence:

        1. The path from the command line, if the user gives one.
        2. The current directory (./filename).
        3. The default path (~/.config/send_cv/filename).

    Args:
        explicit_path (str | None): Path from the command line, if any.
        filename (str): Name of the file to find in the current directory.
        default_path (Path): Path to use if the other two are not available.

    Returns:
        Path: Path of the resolved file.
    """
    if explicit_path:
        return Path(explicit_path).expanduser().resolve()
    local_file = Path(filename)
    if local_file.exists():
        return local_file.resolve()
    return default_path.resolve()


def load_config(config_path: Path) -> EmailConfig:
    """Read the message template and make sure that it is correct.

    Args:
        config_path (Path): Path to config.toml.

    Returns:
        EmailConfig: Data from the configuration file.

    Raises:
        FileNotFoundError: The configuration file does not exist.
        ValueError: A required key is missing, or its value is not correct.
    """
    if not config_path.exists():
        msg = (
            f"Configuration file not found at {config_path}. "
            "Create the file, or use a different --config argument."
        )
        raise FileNotFoundError(msg)

    data = parse_toml(config_path)

    if "subject" not in data or not isinstance(data["subject"], str):
        msg = f"Missing or not correct 'subject' value in {config_path}"
        raise ValueError(msg)

    if "message" not in data or not isinstance(data["message"], str):
        msg = f"Missing or not correct 'message' value in {config_path}"
        raise ValueError(msg)

    attachment_raw = data.get("attachment_path", "")
    if not isinstance(attachment_raw, str):
        msg = f"'attachment_path' must be a string in {config_path}"
        raise TypeError(msg)

    return {
        "subject": data["subject"],
        "message": data["message"],
        "attachment_path": attachment_raw,
    }


def load_credentials(
    credentials_path: Path,
    *,
    require_password: bool = True,
) -> tuple[Sender, Password, Host, Port]:
    """Read the SMTP credentials and make sure that they are correct.

    Args:
        credentials_path (Path): Path to credentials.toml.
        require_password (bool): If True, the password is necessary. Use
            False for a dry run.

    Returns:
        tuple[Sender, Password, Host, Port]: The sender address, the password,
            the host, and the port.

    Raises:
        FileNotFoundError: The credentials file does not exist.
        ValueError: A required value is missing, or it is a placeholder.
    """
    if not credentials_path.exists():
        msg = (
            f"Credentials file not found at {credentials_path}. "
            "Create the file, or use a different --credentials argument."
        )
        raise FileNotFoundError(msg)

    data = parse_toml(credentials_path)

    raw_smtp = data.get("smtp")
    if not isinstance(raw_smtp, dict):
        msg = f"Credentials file {credentials_path} must have an [smtp] table"
        raise TypeError(msg)

    # TOML values can have any type, so the code makes sure of each field.
    smtp_data = cast("dict[str, Any]", raw_smtp)

    raw_sender = smtp_data.get("sender")
    sender = raw_sender.strip() if isinstance(raw_sender, str) else ""
    if (
        not sender
        or sender == "your.email@gmail.com"
        or not EMAIL_PATTERN.match(sender)
    ):
        msg = (
            f"Set a correct sender address in {credentials_path}, "
            "under [smtp.sender]"
        )
        raise ValueError(msg)

    raw_password = smtp_data.get("password", "")
    if not isinstance(raw_password, str):
        msg = f"The password must be a string in {credentials_path}"
        raise TypeError(msg)
    password = raw_password.strip()
    if require_password and (
        not password or password == "your-app-password"  # noqa: S105
    ):
        msg = (
            f"Set a correct password in {credentials_path}, "
            "under [smtp.password]"
        )
        raise ValueError(msg)

    raw_host = smtp_data.get("host", DEFAULT_SMTP_HOST)
    if not isinstance(raw_host, str):
        msg = f"SMTP host '{raw_host}' in {credentials_path} is not a string"
        raise TypeError(msg)
    host = raw_host.strip() or DEFAULT_SMTP_HOST

    raw_port = smtp_data.get("port", DEFAULT_SMTP_PORT)
    try:
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        msg = f"SMTP port '{raw_port}' in {credentials_path} is not a number"
        raise ValueError(msg) from exc
    if not 0 < port < 65536:
        msg = f"SMTP port {port} in {credentials_path} must be between 1 and 65535"
        raise ValueError(msg)

    return Sender(sender), Password(password), Host(host), Port(port)


def resolve_cv_path(
    explicit_cv: str | None,
    config: EmailConfig,
) -> Path:
    """Find the CV file and return its absolute path.

    Args:
        explicit_cv (str | None): Path from the --cv option, if any.
        config (EmailConfig): Data from the configuration file.

    Returns:
        Path: Absolute path of the CV file.

    Raises:
        ValueError: No CV path is given, or the path in config.toml is
            relative.
        FileNotFoundError: The CV file does not exist.
    """
    if explicit_cv:
        cv_path = Path(explicit_cv).expanduser().resolve()
    else:
        attachment_raw = config.get("attachment_path")
        if not attachment_raw or not attachment_raw.strip():
            msg = (
                "No CV path is given. Set 'attachment_path' in config.toml, "
                "or use the --cv option."
            )
            raise ValueError(msg)

        expanded = Path(attachment_raw).expanduser()
        if not expanded.is_absolute():
            msg = (
                f"'attachment_path' in config.toml must be an absolute path, "
                f"not '{attachment_raw}'"
            )
            raise ValueError(msg)
        cv_path = expanded.resolve()

    if not cv_path.exists():
        msg = f"CV file not found at {cv_path}"
        raise FileNotFoundError(msg)

    return cv_path


def configure_logging(loglevel: str) -> None:
    """Set the log level and the format of the log lines.

    Args:
        loglevel (str): Log level name, for example "info" or "debug".
    """
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=loglevel.upper(),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logger.setLevel(loglevel.upper())
    logger.debug("The log level is %s", getLevelName(logger.level))


def path_option_help(
    description: str, filename: str, default_path: Path
) -> str:
    """Return the help text of an option that accepts a file path.

    The text describes the search order of resolve_config_path, which an
    argparse default cannot express.

    Args:
        description (str): Description of the option.
        filename (str): Name of the file in the current directory.
        default_path (Path): Path to use if the current directory has no
            such file.

    Returns:
        str: Help text for the option.
    """
    return f"{description} (default: ./{filename} or {default_path})"


def parse_args() -> argparse.Namespace:
    """Build the command-line parser and return the parsed arguments.

    Returns:
        argparse.Namespace: The options and arguments from the command line.
    """

    class Formatter(argparse.RawDescriptionHelpFormatter):
        """Keep the raw layout and add the default of each option.

        ArgumentDefaultsHelpFormatter adds the default of every argument,
        including the ones that carry no information, for example None and
        False. This formatter adds only a default that tells the user
        something.
        """

        @override
        def _get_help_string(self, action: argparse.Action) -> str:
            """Return the help text of an argument."""
            help_text = action.help or ""
            default = action.default
            if (
                default is None
                or default is argparse.SUPPRESS
                or isinstance(default, bool)
            ):
                return help_text
            return f"{help_text} (default: %(default)s)"

    parser = argparse.ArgumentParser(
        description="Send application emails with a CV attached.",
        epilog=textwrap.dedent("""
                Configuration:
                    - The configuration file holds the subject, the message,
                      and attachment_path.
                    - The credentials file holds [smtp] sender, password, host,
                      and port.

                Sent log:
                    The script writes each recipient to the sent log after a
                    successful send.
                    The log file is the --sent-log option.
                    A later run skips the recipients in the log.
                """),
        formatter_class=Formatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e",
        "--emails",
        type=str,
        nargs="+",
        help="Email address of each recipient",
    )
    group.add_argument(
        "-f",
        "--emails-files",
        type=str,
        nargs="+",
        help="Path to each file with email addresses",
    )

    parser.add_argument(
        "--config",
        type=str,
        help=path_option_help(
            "Path to the configuration file",
            CONFIG_FILENAME,
            DEFAULT_CONFIG_PATH,
        ),
    )
    parser.add_argument(
        "--credentials",
        type=str,
        help=path_option_help(
            "Path to the credentials file",
            CREDENTIALS_FILENAME,
            DEFAULT_CREDENTIALS_PATH,
        ),
    )
    parser.add_argument(
        "--cv",
        type=str,
        help="Path to the CV file to attach (overrides attachment_path in "
        f"{CONFIG_FILENAME})",
    )
    parser.add_argument(
        "-b",
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Number of emails in each batch",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Print the emails and do not send them",
    )
    parser.add_argument(
        "--sent-log",
        type=str,
        default=str(DEFAULT_SENT_LOG_PATH),
        help="File that records the recipients of each email. A later run "
        "skips the recipients in this file",
    )
    parser.add_argument(
        "-l",
        "-log",
        "--loglevel",
        default=DEFAULT_LOG_LEVEL,
        choices=LOG_LEVELS,
        help="Set the log level",
    )
    return parser.parse_args()


def _receivers_from_args(args: argparse.Namespace) -> list[str]:
    """Return the recipient addresses from the command line.

    Args:
        args (argparse.Namespace): The options and arguments from the command
            line.

    Returns:
        list[str]: Addresses from --emails, or from the files that
            --emails-files names.

    Raises:
        ValueError: No recipient is given, or an address is not correct.
    """
    if args.emails:
        receivers = [email.strip() for email in args.emails]
        invalid_emails = [
            email for email in receivers if not EMAIL_PATTERN.match(email)
        ]
        if invalid_emails:
            msg = f"These email addresses are not correct: {', '.join(invalid_emails)}"
            raise ValueError(msg)
        logger.debug(
            "Recipient addresses from the command line: %s", receivers
        )
        return receivers

    if args.emails_files:
        logger.debug(
            "Recipient addresses from the files: %s", args.emails_files
        )
        emails_file_paths: Iterable[Path] = (
            Path(path).expanduser() for path in args.emails_files
        )
        receivers = load_emails_from_files(emails_file_paths)
        if len(receivers) == 0:
            msg = f"No email addresses in the files '{args.emails_files}'"
            raise ValueError(msg)
        return receivers

    # The argument group makes this impossible in practice.
    msg = "No recipient addresses are given"
    raise ValueError(msg)


def pending_receivers(
    args: argparse.Namespace, sent_log_path: Path
) -> list[str]:
    """Return the recipients that still need an email.

    The function removes duplicate addresses first. Then it removes the
    addresses in the sent log, so a second run continues where the first run
    stopped.

    Args:
        args (argparse.Namespace): The options and arguments from the command
            line.
        sent_log_path (Path): Path to the sent log.

    Returns:
        list[str]: The addresses that do not have an email yet.

    Raises:
        ValueError: No recipient is given, or an address is not correct.
    """
    receivers, duplicate_count = deduplicate_emails(_receivers_from_args(args))
    if duplicate_count > 0:
        logger.warning("Removed %d duplicate addresses", duplicate_count)

    sent_recipients = load_sent_log(sent_log_path)
    if sent_recipients:
        receivers, skipped_count = filter_unsent(receivers, sent_recipients)
        if skipped_count > 0:
            logger.info(
                "Skipped %d recipients. They are in the sent log %s",
                skipped_count,
                sent_log_path,
            )

    return receivers


# ---------------------------------------------------------------------------
# Mail composition
# ---------------------------------------------------------------------------
def recipients_of(
    email: EmailMessage,
    *,
    exclude: str | None = None,
) -> list[str]:
    """Return the recipient addresses from the To and Bcc headers.

    Args:
        email (EmailMessage): The email message.
        exclude (str | None): An address to omit, for example the sender.

    Returns:
        list[str]: The recipient addresses.
    """
    normalized_exclude = exclude.strip().lower() if exclude else None

    addresses: list[str] = []
    for header in ("To", "Bcc"):
        for value in email.get_all(header, []):
            for part in str(value).split(","):
                stripped = part.strip()
                if stripped and stripped.lower() != normalized_exclude:
                    addresses.append(stripped)

    return addresses


def create_emails(
    sender: Sender,
    receivers: list[str],
    *,
    config: EmailConfig,
    batch_size: int,
) -> list[EmailMessage]:
    """Build the emails for the recipients.

    The subject and the message body come from the configuration file. The
    function also sets the Reply-To and Date headers. The emails contain
    plain text.

    The function puts the recipients in groups of `batch_size`, because email
    providers limit the number of messages:

        - If `batch_size` is 1, the recipient goes in the To header.
        - If `batch_size` is more than 1, the recipients go in the Bcc header.
          The sender goes in the To header, because some filters reject a
          message with an empty To header.

    Args:
        sender (Sender): Sender email address.
        receivers (list[str]): Recipient email addresses.
        config (EmailConfig): The subject and the message for the emails.
        batch_size (int): Number of recipients in each message.

    Returns:
        list[EmailMessage]: The email messages.
    """

    def build_single_email_message(
        sender: Sender,
        receivers: Sequence[str],
        config: EmailConfig,
    ) -> EmailMessage:
        """Build one email message and return it.

        The function sets the From, To, Bcc, Subject, Reply-To, and Date
        headers. It fills the body with the message from the configuration.

        Args:
            sender (Sender): Sender email address.
            receivers (Sequence[str]): One or more recipient email addresses.
            config (EmailConfig): The subject and the message for the email.

        Returns:
            EmailMessage: The email message.
        """
        email = EmailMessage()
        email["From"] = sender

        if len(receivers) == 1:
            email["To"] = receivers[0].strip()
        else:
            email["To"] = sender  # Some filters reject an empty To header.
            # The recipients do not see each other.
            email["Bcc"] = ",".join(map(str.strip, receivers))

        email["Subject"] = config["subject"]
        email["Reply-To"] = sender
        email["Date"] = localtime()
        email["Message-ID"] = make_msgid(domain=sender.split("@", 1)[1])
        email["User-Agent"] = f"{PROJECT_NAME}/{PROJECT_VERSION}"
        # The body is plain text.
        email.set_content(config["message"], subtype="plain", charset="utf-8")

        return email

    emails: list[EmailMessage] = []

    for i, receiver_pack in enumerate(
        itertools.batched(receivers, batch_size, strict=False)
    ):
        email = build_single_email_message(sender, receiver_pack, config)

        # Write the headers to the debug log. The Bcc header holds the
        # recipient addresses, so they stay out of the log.
        logger.debug("Email %d headers:", i)
        for header, value in email.items():
            if header.lower() == "bcc":
                logger.debug(
                    "\tBcc: %d recipients",
                    len(recipients_of(email, exclude=sender)),
                )
                continue
            logger.debug("\t%s: %s", header, value)

        emails.append(email)

    return emails


def attach_cv(
    emails: Sequence[EmailMessage],
    explicit_cv: str | None,
    config: EmailConfig,
) -> tuple[str, bytes, str, str]:
    """Attach the CV file to every email.

    Args:
        emails (Sequence[EmailMessage]): Messages to attach the CV to.
        explicit_cv (str | None): Path from the --cv option, if any.
        config (EmailConfig): Data from the configuration file.

    Returns:
        tuple[str, bytes, str, str]: The file name, the file data, and the
            main type and subtype.

    Raises:
        ValueError: No CV path is given, or the path is relative.
        FileNotFoundError: The CV file does not exist.
    """
    cv_path = resolve_cv_path(explicit_cv, config)
    cv_name, cv_data = load_file(cv_path)

    mime_type, _ = mimetypes.guess_type(cv_path)
    content_type = mime_type or "application/octet-stream"
    maintype, subtype = content_type.split("/", 1)
    logger.debug("MIME type: %s/%s", maintype, subtype)

    for email in emails:
        email.add_attachment(
            cv_data,
            maintype=maintype,
            subtype=subtype,
            filename=cv_name,
        )

    return cv_name, cv_data, maintype, subtype


def print_dry_run(
    emails: Sequence[EmailMessage],
    receivers: Sequence[str],
    sender: Sender,
    attachment: tuple[str, bytes, str, str],
) -> None:
    """Print the emails without sending them.

    The function does not connect to a server.

    Args:
        emails (Sequence[EmailMessage]): The emails to print.
        receivers (Sequence[str]): Recipient addresses.
        sender (Sender): Sender address. The function does not count it as a
            recipient.
        attachment (tuple[str, bytes, str, str]): File name, file data, main
            type, and subtype of the CV attachment.
    """
    cv_name, cv_data, maintype, subtype = attachment
    print(f"[DRY RUN] Emails: {len(emails)} | Recipients: {len(receivers)}")
    print(
        f"[DRY RUN] Attachment: {cv_name} "
        f"({len(cv_data)} bytes, {maintype}/{subtype})"
    )
    for i, email in enumerate(emails, start=1):
        bcc = email.get("Bcc", "")
        print(
            f"[DRY RUN] Email {i}: To={email['To']} | "
            f"Bcc={bcc or '-'} | Subject={email['Subject']} | "
            f"Recipients={len(recipients_of(email, exclude=sender))}"
        )


# ---------------------------------------------------------------------------
# SMTP transport
# ---------------------------------------------------------------------------
def _open_smtp_connection(
    sender: Sender,
    password: Password,
    host: Host = DEFAULT_SMTP_HOST,
    port: Port = DEFAULT_SMTP_PORT,
) -> smtplib.SMTP_SSL:
    """Open an SMTP connection and log in.

    If the server is not available, the function tries again up to
    ATTEMPT_LIMIT times. The wait between two attempts doubles each time. The
    function does not try again if the server rejects the credentials.

    Args:
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.

    Returns:
        smtplib.SMTP_SSL: An SMTP connection that is ready to use.

    Raises:
        smtplib.SMTPAuthenticationError: The server rejected the credentials.
        OSError: The connection cannot be established.
    """
    last_exc: Exception | None = None

    for attempt in range(1, ATTEMPT_LIMIT + 1):
        smtp: smtplib.SMTP_SSL | None = None
        try:
            smtp = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT)
            smtp.login(sender, password)
        except (smtplib.SMTPException, OSError) as exc:
            if smtp is not None:
                smtp.close()
            if isinstance(exc, smtplib.SMTPAuthenticationError):
                raise
            last_exc = exc
            if attempt == ATTEMPT_LIMIT:
                break
            logger.warning(
                "Cannot connect to the SMTP server (attempt %d/%d): %s",
                attempt,
                ATTEMPT_LIMIT,
                exc,
            )
            sleep(2**attempt + uniform(0, 1))
        else:
            return smtp

    if last_exc is not None:
        raise last_exc
    msg = "Cannot connect to the SMTP server"
    raise OSError(msg)


def _reconnect(
    smtp: smtplib.SMTP_SSL,
    sender: Sender,
    password: Password,
    host: Host,
    port: Port,
) -> smtplib.SMTP_SSL:
    """Close a connection and return a new connection.

    Args:
        smtp (smtplib.SMTP_SSL): The connection to replace. It can be broken,
            and then closing it does nothing.
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.

    Returns:
        smtplib.SMTP_SSL: A new SMTP connection that is ready to use.
    """
    smtp.close()
    return _open_smtp_connection(sender, password, host=host, port=port)


def _is_transient_error(exc: Exception) -> bool:
    """Return True if the server deferred the email.

    Only the temporary codes 421, 450, 451, and 452 make a new attempt safe.
    The server did not accept the email, so a new attempt cannot deliver it
    twice. Code 421 means that the server closes the channel.

    If the server refuses all recipients, a new attempt is safe only when
    every refusal is temporary.

    Transport errors (timeouts, resets, and closed connections) are not safe
    to retry, although they are usually temporary. The message can arrive
    before the error appears.

    Args:
        exc (Exception): The error from the send operation.

    Returns:
        bool: True if a new attempt cannot deliver the email twice.
    """
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        # This error occurs when the server refuses all recipients. The
        # values are (code, error) pairs.
        codes = {code for code, _ in exc.recipients.values()}
        return bool(codes) and codes <= TEMPORARY_SMTP_CODES
    if isinstance(exc, smtplib.SMTPResponseException):
        return exc.smtp_code in TEMPORARY_SMTP_CODES
    return False


def _requires_reconnect(exc: Exception) -> bool:
    """Return True if a send error made the connection unusable.

    Code 421 means that the server closes the channel, so the script must
    open a new connection. The same is true after SMTPServerDisconnected and
    after a transport error, for example a timeout or a reset.

    Codes 450, 451, and 452, and permanent rejections, keep the connection
    usable.

    Args:
        exc (Exception): The error from the send operation.

    Returns:
        bool: True if the script must open a new connection.
    """
    if getattr(exc, "smtp_code", None) == 421:
        return True
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return True
    return isinstance(exc, OSError) and not isinstance(
        exc, smtplib.SMTPException
    )


class _SendOutcome(NamedTuple):
    """What happened to one email.

    Attributes:
        connection (smtplib.SMTP_SSL): The connection for the next email. It
            differs from the argument when the function opened a new one.
        sent (bool): True if the server accepted the message.
        refused (list[tuple[str, str]]): One (address, reason) entry per
            recipient that the server refused while it accepted the message.
        reason (str): Why the email was not sent. It is empty when the server
            accepted the message.
        unreachable (str | None): Why the SMTP server is unreachable, or
            None. The run cannot continue after this value is set.
    """

    connection: smtplib.SMTP_SSL
    sent: bool
    refused: list[tuple[str, str]]
    reason: str
    unreachable: str | None


def _swap_connection(
    smtp: smtplib.SMTP_SSL,
    sender: Sender,
    password: Password,
    host: Host,
    port: Port,
) -> tuple[smtplib.SMTP_SSL, str | None]:
    """Open a new connection in place of a broken one.

    Args:
        smtp (smtplib.SMTP_SSL): The connection to replace.
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.

    Returns:
        tuple[smtplib.SMTP_SSL, str | None]: The new connection and None. If
            the server is unreachable, the old connection and the reason.
    """
    try:
        return _reconnect(smtp, sender, password, host, port), None
    except (smtplib.SMTPException, OSError) as exc:
        return smtp, f"SMTP server unreachable: {exc}"


def _refused_recipients(
    refused: dict[str, tuple[int, bytes]],
) -> list[tuple[str, str]]:
    """Return one (address, reason) entry for each refused recipient.

    Args:
        refused (dict[str, tuple[int, bytes]]): The mapping that
            smtplib.SMTP.send_message returns for the recipients that the
            server rejects.

    Returns:
        list[tuple[str, str]]: The address and the reason of each refusal.
    """
    return [
        (address, f"code {code}: {message.decode(errors='replace')}")
        for address, (code, message) in refused.items()
    ]


def _error_reason(exc: Exception) -> str:
    """Return a readable reason for a failure to send.

    The plain text of an SMTP error contains the code and the message of the
    server only inside a tuple, for example (550, b'5.7.1 spam'). The
    function writes them in the same shape as a refused recipient.

    Args:
        exc (Exception): The error from the send operation.

    Returns:
        str: The reason for the log line.
    """
    if isinstance(exc, smtplib.SMTPResponseException):
        message = exc.smtp_error
        text = (
            message.decode(errors="replace")
            if isinstance(message, bytes)
            else str(message)
        )
        return f"code {exc.smtp_code}: {text}"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "; ".join(
            f"{address}: {reason}"
            for address, reason in _refused_recipients(exc.recipients)
        )
    return str(exc)


def _send_one_email(
    smtp: smtplib.SMTP_SSL,
    email: EmailMessage,
    *,
    sender: Sender,
    password: Password,
    host: Host,
    port: Port,
    label: str,
) -> _SendOutcome:
    """Send one email and try again after a temporary rejection.

    The function tries again only after a temporary rejection (codes 421,
    450, 451, and 452). It waits between the attempts and opens a new
    connection if the server closed the channel. Those codes mean that the
    server did not accept the email, so a new attempt cannot deliver it
    twice.

    The function does not try again after a transport error (a timeout, a
    reset, or a closed connection). The email can arrive before the error
    appears.

    Args:
        smtp (smtplib.SMTP_SSL): The connection to send through.
        email (EmailMessage): The message to send.
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.
        label (str): Position of the email in the run, for the log lines.

    Returns:
        _SendOutcome: What happened to the email.
    """
    for attempt in range(1, ATTEMPT_LIMIT + 1):
        try:
            # send_message returns {refused_addr: (code, error)} for the
            # recipients that the server rejects. The other recipients still
            # get the message. The call raises an error if the server
            # rejects every recipient.
            refused = smtp.send_message(email)
        except (smtplib.SMTPException, OSError) as exc:
            transient = _is_transient_error(exc)
            if transient and attempt < ATTEMPT_LIMIT:
                logger.warning(
                    "Temporary SMTP error for email %s (attempt %d/%d): %s",
                    label,
                    attempt,
                    ATTEMPT_LIMIT,
                    exc,
                )
                sleep(2**attempt + uniform(0, 1))
                if _requires_reconnect(exc):
                    # The connection is closed. Open a new one. If the
                    # server is unreachable, a new attempt is not possible.
                    smtp, unreachable = _swap_connection(
                        smtp, sender, password, host, port
                    )
                    if unreachable is not None:
                        return _SendOutcome(
                            smtp,
                            sent=False,
                            refused=[],
                            reason=f"not sent: {unreachable}",
                            unreachable=unreachable,
                        )
                continue

            # The server rejects the message for good, or a transport error
            # occurred. A new attempt can deliver the message twice, so the
            # function records the failure and continues with the next email.
            reason = (
                f"failed after {ATTEMPT_LIMIT} attempts: {_error_reason(exc)}"
                if transient
                else _error_reason(exc)
            )
            unreachable = None
            if _requires_reconnect(exc):
                # If this fails, the next email records the error.
                smtp, unreachable = _swap_connection(
                    smtp, sender, password, host, port
                )
            return _SendOutcome(
                smtp,
                sent=False,
                refused=[],
                reason=reason,
                unreachable=unreachable,
            )
        else:
            return _SendOutcome(
                smtp,
                sent=True,
                refused=_refused_recipients(refused),
                reason="",
                unreachable=None,
            )

    # The loop returns a result on the last attempt, so it never gets here.
    msg = "The attempt loop returned no result"
    raise AssertionError(msg)


def send_emails(
    sender: Sender,
    password: Password,
    emails: Sequence[EmailMessage],
    *,
    host: Host = DEFAULT_SMTP_HOST,
    port: Port = DEFAULT_SMTP_PORT,
    on_sent: Callable[[Sequence[str]], None] | None = None,
) -> int:
    """Send the emails through the SMTP server.

    The function opens a secure connection, logs in, and sends each email.

    The function tries again only after a temporary rejection (codes 421,
    450, 451, and 452). It waits between the attempts and opens a new
    connection if necessary. Those codes mean that the server did not accept
    the email, so a new attempt cannot deliver it twice.

    The function skips an email that it cannot send, continues with the next
    one, and logs all the failures at the end. It sends only the accepted
    recipients to `on_sent`. If the server becomes unreachable during the
    run, the function records the remaining emails as failures and returns,
    so no failure report is lost.

    Each EmailMessage object already contains the recipient addresses.

    Args:
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        emails (Sequence[EmailMessage]): EmailMessage objects to send.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.
        on_sent (Callable[[Sequence[str]], None] | None): A function that
            receives the accepted addresses after each send, for example to
            write them to the sent log.

    Returns:
        int: The number of messages that the server accepted.

    Raises:
        smtplib.SMTPAuthenticationError: The server rejected the credentials.
        OSError: The SMTP connection cannot be established.
    """
    smtp = _open_smtp_connection(sender, password, host=host, port=port)
    sent_messages = 0
    # One (recipients, reason) entry per email that was not sent.
    failed_emails: list[tuple[list[str], str]] = []
    # One (address, reason) entry per recipient that the server refused
    # while the email itself was sent.
    refused_recipients: list[tuple[str, str]] = []
    # The reason why the SMTP server is unreachable, or None. When the
    # server is unreachable, the remaining emails cannot be sent.
    server_error: str | None = None

    try:
        for i, email in enumerate(emails, start=1):
            recipients = recipients_of(email, exclude=sender)

            if server_error is not None:
                # The server is unreachable. This email was not attempted.
                failed_emails.append(
                    (recipients, f"not attempted: {server_error}")
                )
                continue

            outcome = _send_one_email(
                smtp,
                email,
                sender=sender,
                password=password,
                host=host,
                port=port,
                label=f"{i}/{len(emails)}",
            )
            smtp = outcome.connection
            server_error = outcome.unreachable

            if not outcome.sent:
                failed_emails.append((recipients, outcome.reason))
            else:
                sent_messages += 1
                # Keep only the recipients that the server accepted.
                refused_set = {
                    address.strip().lower() for address, _ in outcome.refused
                }
                accepted = [
                    recipient
                    for recipient in recipients
                    if recipient.strip().lower() not in refused_set
                ]
                refused_recipients.extend(outcome.refused)

                # Write the recipients now. If the run stops later, the next
                # run does not email them again.
                if accepted and on_sent is not None:
                    on_sent(accepted)

            if server_error is None and i < len(emails):
                wait_time = uniform(*WAIT_TIMES)
                logger.debug(
                    "Wait %.2f seconds before the next email",
                    wait_time,
                )
                sleep(wait_time)
    finally:
        smtp.close()

    if failed_emails:
        logger.error(
            "%d of %d emails failed to send",
            len(failed_emails),
            len(emails),
        )
        for recipients, reason in failed_emails:
            logger.error(
                "Failed to send to %s: %s", ", ".join(recipients), reason
            )

    if refused_recipients:
        logger.error(
            "The server refused %d recipients:", len(refused_recipients)
        )
        for address, reason in refused_recipients:
            logger.error("Refused %s: %s", address, reason)

    return sent_messages


def main() -> None:
    """Read the configuration and send the emails."""
    # Read the command line.
    args = parse_args()

    if args.batch_size < 1:
        msg = "The batch size must be 1 or more"
        raise ValueError(msg)

    configure_logging(args.loglevel)

    # Create the default directory and the templates if they are missing.
    ensure_config_scaffold(DEFAULT_CONFIG_DIR)

    # Read the configuration file.
    config_path = resolve_config_path(
        args.config, CONFIG_FILENAME, DEFAULT_CONFIG_PATH
    )
    logger.debug("Configuration file: %s", config_path)
    config = load_config(config_path)

    # Read the credentials.
    credentials_path = resolve_config_path(
        args.credentials, CREDENTIALS_FILENAME, DEFAULT_CREDENTIALS_PATH
    )
    logger.debug("Credentials file: %s", credentials_path)
    sender, password, host, port = load_credentials(
        credentials_path, require_password=not args.dry_run
    )

    # Get the recipients. The function removes duplicates and the addresses
    # that are already in the sent log.
    sent_log_path = Path(args.sent_log).expanduser().resolve()
    receivers = pending_receivers(args, sent_log_path)

    if not receivers:
        logger.info("No recipients are left to email.")
        return

    emails = create_emails(
        sender,
        receivers,
        config=config,
        batch_size=args.batch_size,
    )
    attachment = attach_cv(emails, args.cv, config)

    # A dry run prints the messages and does not connect to a server.
    if args.dry_run:
        print_dry_run(emails, receivers, sender, attachment)
        return

    # Send the messages.
    sent_count = send_emails(
        sender,
        password,
        emails,
        host=host,
        port=port,
        on_sent=lambda sent: append_to_sent_log(sent_log_path, sent),
    )
    logger.info(
        "Sent %d of %d emails with attachment %s",
        sent_count,
        len(emails),
        attachment[0],
    )
    logger.debug("All recipients: %s", receivers)


def _exit_with_error(exc: Exception) -> NoReturn:
    """Log a fatal error and stop the script.

    The function logs the message at error level. It logs the traceback at
    debug level, so a simple configuration mistake stays easy to read.

    Args:
        exc (Exception): The error that stopped the run.
    """
    logger.debug("Traceback:", exc_info=exc)
    if isinstance(exc, smtplib.SMTPResponseException):
        logger.error("SMTP error %s: %s", exc.smtp_code, exc.smtp_error)
    else:
        logger.error("%s", exc)
    sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (
        TypeError,
        ValueError,
        OSError,
        smtplib.SMTPResponseException,
    ) as exc:
        _exit_with_error(exc)
