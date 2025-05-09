from rich.console import Console
from rich.text import Text
from rich.prompt import Prompt

def prompt_ask(
    console: Console,
    bracket_content: str,
    prompt_indicator: str = "~",
    password: bool = False
) -> str:
    prompt_text_assembly = Text.assemble(
        ("┌─[", "dim white"),
        (bracket_content, "prompt_bracket_text"),
        ("]─────[", "dim white"),
        ("#", "prompt_symbol"),
        ("]\n└─[", "dim white"),
        (prompt_indicator, "prompt_bracket_text"),
        ("]────► ", "prompt_symbol")
    )
    if password:
        return Prompt.ask(
            prompt_text_assembly,
            password=False,
            console=console
        ).strip()
    else:
        console.print(prompt_text_assembly, end="")
        user_input = console.input()
        return user_input.strip()
