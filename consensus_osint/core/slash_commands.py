"""Discoverable session commands; completion never runs an action."""

COMMANDS = (
    ("/config", "Change search and display settings"),
    ("/help", "Explain searches, commands and controls"),
    ("/user", "Search a username"),
    ("/email", "Search an email address"),
    ("/phone", "Search a phone number"),
    ("/bulk", "Search several identifiers"),
    ("/last", "View the latest results"),
    ("/save", "Save the latest results as a report"),
    ("/examples", "Show example searches"),
    ("/info", "Show paths, version and repository"),
    ("/update", "Install the latest Consensus release"),
    ("/updates", "Open installation, updates and recovery"),
    ("/history", "Reopen or manage optional saved searches"),
    ("/investigations", "Save named investigations, notes and review decisions"),
    ("/followup", "Continue, search new sources or compare results"),
    ("/continue", "Continue a full search using completed results"),
    ("/new-sources", "Search lookup sources added since a saved search"),
    ("/recheck", "Recheck saved identifiers and compare changes"),
    ("/changes", "Show changes since the previous search"),
    ("/terminal", "Set up the Windows Terminal tab icon"),
    ("/about", "About Consensus and the Society"),
    ("/menu", "Show the welcome page"),
    ("/reset", "Reset settings and forget latest results"),
    ("/exit", "Close Consensus"),
)


def completer(enabled):
    from prompt_toolkit.completion import Completer, Completion

    class SlashCompleter(Completer):
        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            if not enabled() or not text.startswith("/") or any(c.isspace() for c in text):
                return
            for command, description in COMMANDS:
                if command.startswith(text.lower()):
                    yield Completion(command, start_position=-len(text), display_meta=description)

    return SlashCompleter()
