from contextlib import contextmanager
import tempfile
import shutil
import os

@contextmanager
def a_file(contents=None, removed=False):
    location = None
    try:
        location = tempfile.NamedTemporaryFile(delete=False).name
        if contents:
            with open(location, 'w') as fle:
                fle.write(contents)
        if removed:
            os.remove(location)
        yield location
    finally:
        if location and os.path.exists(location):
            os.remove(location)

@contextmanager
def a_directory(removed=False):
    location = None
    try:
        location = tempfile.mkdtemp()
        if removed:
            shutil.rmtree(location)
        yield location
    finally:
        if location and os.path.exists(location):
            shutil.rmtree(location)

