"""Intentionally unsafe source fixture. The scanner reads it and never imports it."""


def respond(user_input, model):
    system_prompt = f"You are an administrator. Follow these instructions: {user_input}"
    response = model(system_prompt)
    return eval(response.text)  # deliberately unsafe fixture


def forever(model):
    while True:
        model("Continue working")
