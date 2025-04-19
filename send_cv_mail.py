#!/usr/bin/python3
import argparse
import logging
import mimetypes
import os
import smtplib
import textwrap
from email.message import EmailMessage
from logging import getLevelName
from pathlib import Path
from typing import Any

import tomllib

# Credentials.
sender = os.environ.get("SAU_MAIL")
# Google wants "app password" instead of my actual password.
password = os.environ.get("SAU_APP_PASSWD")


def main():
    # Set up command-line argument parsing.
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging.
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    logger.setLevel(args.loglevel.upper())
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    # Check if sender and password are set.
    if sender is None or password is None:
        msg = "Environment variables SAU_MAIL and SAU_APP_PASSWD must be set"
        logger.error(msg)
        raise ValueError(msg)

    # Read configuration file.
    config_path = Path("~/.config/send_cv.toml").expanduser()

    if not config_path.exists():
        msg = f"Configuration file not found at {config_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)
    logger.debug("Configuration file found at %s", config_path)

    # Read configuration file.
    config = parse_toml(config_path, logger)

    receivers: list[str] = args.receiver_emails

    # Create message.
    email = EmailMessage()
    email["From"] = sender
    email["To"] = ",".join(receivers)
    email["Subject"] = config["subject"]
    email.set_content(config["message"])

    # Load file.
    file_path = Path("~/Documents/CV/TR/OzanMalciBilMuhCV.pdf").expanduser()
    file_data, file_name = load_file(file_path, logger)

    # Determine MIME type.
    content_type = (
        mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    )
    maintype, subtype = content_type.split("/", 1)
    logger.debug("Determined MIME type: %s/%s", maintype, subtype)

    # Add attachment.
    email.add_attachment(
        file_data, maintype=maintype, subtype=subtype, filename=file_name
    )

    # Send email.
    try:
        send_email(
            sender,
            password,
            email,
            logger,
        )
    except smtplib.SMTPResponseException as resp_exc:
        logger.exception(
            "SMTP Error: %s - %s",
            resp_exc.smtp_code,
            resp_exc.smtp_error,
        )
        raise
    except smtplib.SMTPException:
        logger.exception("Failed to send email due to SMTP error")
        raise
    else:
        logger.info("Email sent to %s with attachment %s", receivers, file_name)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Set up command-line argument parsing.

    Returns:
        argparse.ArgumentParser: Configured argument parser.

    """
    parser = argparse.ArgumentParser(
        description="Email sender script that sends an email with a attachment.",
        epilog=textwrap.dedent("""
                Environment variables required:
                    SAU_MAIL: The sender's email address
                    SAU_APP_PASSWD: The sender's password
                """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "receiver_emails",
        type=str,
        nargs="+",
        help="Email address of the recipient(s)",
    )

    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        help="Provide logging level",
    )
    return parser


def load_file(file_path: Path, logger: logging.Logger) -> tuple[bytes, str]:
    """
    Load a file and return its content and name.

    Args:
        file_path (Path): Path to the file.
        logger (logging.Logger): Logger instance for logging.

    Returns:
        tuple[bytes, str]: Tuple containing the content and its name.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.

    """
    if not file_path.exists():
        msg = f"file not found at {file_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    # Read file.
    try:
        with file_path.open("rb") as fp:
            file_data = fp.read()
            file_name = file_path.name
            logger.debug("Successfully read file: %s", file_name)
    except (OSError, PermissionError) as exc:
        msg = f"Failed to read file: {exc}"
        logger.exception(msg)
        raise

    return file_data, file_name


def parse_toml(toml_path: Path, logger: logging.Logger) -> dict[str, Any]:
    """
    Parse a TOML file and return its contents as a dictionary.

    Args:
        toml_path (Path): Path to the TOML file.
        logger (logging.Logger): Logger instance for logging.

    Returns:
        dict[str, Any]: Dictionary containing the parsed TOML data.

    Raises:
        OSError: If the file cannot be read.
        tomllib.TOMLDecodeError: If the file cannot be parsed.

    """
    try:
        with Path.open(toml_path, "rb") as f:
            data = tomllib.load(f)
            logger.debug("Successfully read configuration file")
    except (OSError, tomllib.TOMLDecodeError) as exc:
        msg = f"Failed to read configuration file: {exc}"
        logger.exception(msg)
        raise OSError(msg) from exc

    return data


def send_email(
    sender: str, password: str, email: EmailMessage, logger: logging.Logger
) -> None:
    """
    Send an email using Gmail's SMTP server.

    This function establishes a secure connection with Gmail's SMTP server,
    logs in using the provided credentials, and sends the pre-constructed email message.

    The reviever's email address is set in the EmailMessage object.

    Args:
        sender (str): The sender's email address
        password (str): The password or app-specific password for the account
        email (EmailMessage): A pre-constructed EmailMessage object to be sent
        logger (logging.Logger): Logger object to record operation status

    Returns:
        None

    Raises:
        smtplib.SMTPAuthenticationError: If authentication fails
        smtplib.SMTPException: If any SMTP-related error occurs during sending

    """
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        logger.debug("Established connection to SMTP server")

        smtp.login(sender, password)
        logger.debug("Successfully logged in to SMTP server")

        smtp.send_message(email)
        logger.debug("Message sent to SMTP server")


if __name__ == "__main__":
    main()
