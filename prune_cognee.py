import os
import shutil
import cognee

def prune():
    import pathlib
    base = pathlib.Path(cognee.__file__).parent
    data_dir = base / ".data_storage"
    sys_dir = base / ".cognee_system"
        
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir, ignore_errors=True)
    if os.path.exists(sys_dir):
        shutil.rmtree(sys_dir, ignore_errors=True)
    print(f"Pruned {data_dir} and {sys_dir}!")

if __name__ == "__main__":
    prune()
