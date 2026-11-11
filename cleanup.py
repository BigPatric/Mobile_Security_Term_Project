import os
import shutil

# Remove all the __pycache__ directories
for root, dirs, files in os.walk('.'):
    for d in dirs:
        if d == '__pycache__':
            shutil.rmtree(os.path.join(root, d))