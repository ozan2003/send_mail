# send_cv_mail

A Python tool that sends application emails with a CV attachment through SMTP.

## Features

- Reads the email subject and body from a TOML configuration file.
- Reads SMTP credentials from a separate TOML file.
- Requires Python 3.13 or newer with no external packages.
- Skips email addresses that you already contacted.

## Configuration

The tool stores configuration files in `~/.config/send_cv/`.
The script creates starter template files automatically on the first run.

### 1. `credentials.toml`

File location: `~/.config/send_cv/credentials.toml`

```toml
[smtp]
sender = "your.email@gmail.com"
password = "your-app-password"
host = "smtp.gmail.com"
port = 465
```

If you use `--dry-run`, `password` is not necessary.
`host` and `port` are optional.

### 2. `config.toml`

File location: `~/.config/send_cv/config.toml`

```toml
subject = "Application for Summer Internship"
attachment_path = "~/Documents/cv.pdf"

message = """
Dear Hiring Team,

Please find attached my CV for your consideration.

Best regards,
"""
```

`attachment_path` must be an absolute path or start with `~`.

On Windows, use forward slashes or single quotes for the path:

- Forward slashes: `attachment_path = "C:/Users/name/Documents/cv.pdf"`
- Single quotes: `attachment_path = 'C:\Users\name\Documents\cv.pdf'`
- User directory: `attachment_path = "~/Documents/cv.pdf"`

## File Search Order

The script searches for files in this order:

1. Command-line options: `--config`, `--credentials`, `--cv`.
2. Current working directory: `./config.toml`, `./credentials.toml`.
3. User configuration directory: `~/.config/send_cv/`.

## Usage

Preview the email output without sending:

```bash
python send_cv_mail.py -e recruiter@example.com --dry-run
```

Send emails to a list from a file in batches of 3:

```bash
python send_cv_mail.py -f emails.txt -b 3
```

Specify custom file paths:

```bash
python send_cv_mail.py -e recruiter@example.com --config ./custom_config.toml --cv ~/Downloads/new_cv.pdf
```

The tool writes sent addresses to `sent_emails.log`.
To change this file path, use the `--sent-log` option.
On the next run, the tool skips addresses that exist in this log.
