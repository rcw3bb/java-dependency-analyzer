"""
logging_group module.

Click group that writes every command-line error to the log.

:author: Ron Webb
:since: 1.6.0
"""

import click

from .logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.6.0"

_logger = setup_logger(__name__)


class LoggingGroup(click.Group):
    """
    Click group that writes every error to the log.

    Click prints usage and command errors straight to stderr, and Python prints
    uncaught exceptions to stderr, so they would otherwise never reach the log
    file.

    :author: Ron Webb
    :since: 1.6.0
    """

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """
        Parse the group arguments, logging any :class:`click.ClickException`.

        :author: Ron Webb
        :since: 1.6.0
        """
        try:
            return super().parse_args(ctx, args)
        except click.ClickException as exc:
            _logger.error("%s", exc.format_message())
            raise

    def invoke(self, ctx: click.Context):
        """
        Invoke the group and log any error before re-raising it.

        Covers usage and command errors, an aborted run and unexpected exceptions.

        :author: Ron Webb
        :since: 1.6.0
        """
        try:
            return super().invoke(ctx)
        except click.ClickException as exc:
            _logger.error("%s", exc.format_message())
            raise
        except click.Abort:
            _logger.error("Aborted by the user.")
            raise
        except Exception:
            _logger.exception("Unexpected error")
            raise
