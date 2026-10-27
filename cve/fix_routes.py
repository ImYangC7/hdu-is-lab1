"""Apply the method authorization check from Gradio upstream PR 6884."""

from pathlib import Path
import gradio

path = Path(gradio.__file__).parent / "routes.py"
source = path.read_text()
old = """            fn = getattr(block, body.fn_name)
            return fn(body.data)"""
new = """            fn = getattr(block, body.fn_name, None)
            if fn is None or not getattr(fn, "_is_server_fn", False):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Function not found.",
                )
            return fn(body.data)"""
if source.count(old) != 1:
    raise RuntimeError("Expected exactly one vulnerable component_server method dispatch.")
path.write_text(source.replace(old, new, 1))
print("Applied upstream method authorization check to", path)
