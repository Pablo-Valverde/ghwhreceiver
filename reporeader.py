from git.exc import GitCommandError
from pathlib import Path
import git
import shutil


def pull(DIR_NAME, REMOTE_URL):
    repo_directory = Path(DIR_NAME)
    for _ in range(0,2):
        try:
            origin = __init_repo__(REMOTE_URL, repo_directory)
            return __pull_rm__(repo_directory, origin)
        except GitCommandError:
            return
    raise RuntimeError("Couldn't pull '%s' to '%s'" % (REMOTE_URL, repo_directory))

def __pull_rm__(repo_path, origin):
    origin.fetch()

    try:
        if origin.refs.__len__() > 0:
            origin.pull(origin.refs[0].remote_head)
        return
    except GitCommandError:
        shutil.rmtree(repo_path, ignore_errors=True)

def __init_repo__(REMOTE_URL, repo_path):
    repo = git.Repo.init(repo_path)

    try:
        repo.delete_remote("origin")
    except GitCommandError:
        pass     

    origin = repo.create_remote("origin", REMOTE_URL)

    return origin
