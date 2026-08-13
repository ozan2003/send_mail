# Send mail

- This script sends email with the school account.
- It reads the email subject and body from a TOML file.
- It adds the CV as an attachment.
- It sends the email to the specified recipient(s).

## Configuration

If you want to use this script without changes, configure the following:

- Set the email address and password as environment variables (`SENDER` and `PASSWORD`).
- `PASSWORD` is only needed for an actual send. `--dry-run` works without it.
- Put the email subject and body in a TOML file. The script reads this file from `CONFIG_FILE_PATH`.
- Set the CV file path in `CV_FILE_PATH`.

Refer to `-h/--help` for usage.

Run with `--dry-run` to preview the emails without sending. The script records sent recipients in `sent_emails.log`.
You can change this file with `--sent-log`. On the next run, the script skips recipients in this log.

## Configuration file

The file given by `CONFIG_FILE_PATH` must be a TOML file that has these keys:

- `subject` (string, required): the email subject line.
- `message` (string, required): the plain-text email body.

Example:

```toml
subject = "Application for Summer Internship"
message = """
Dear Hiring Team,

I am writing to apply for the summer internship position.
My CV is attached.

Best regards.
"""
```

Both keys are required. A missing key stops the run with a `KeyError`.
