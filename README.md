# Gogeit: A barebones Git-Like VCS in Go

This is a resume project with the main goal to practice GO and learn more of the innerworkings of git.
## Features
Gogeit supports fundamental local Git operations:

| Syntax | Description |
| ----------- | ----------- |
| init | Initializes a .Gogeit repository |
| add <file_path> | Stages file changes to the index |
| commit -m "<message>" | Creates a new commit from the staged changes |
| add show <file_path> | Shows the content of a file from the latest commit |
| cat-file -p <object_hash> | Prints raw Git objects (blobs, trees, commits) by hash |
| help | Lists available commands |

```
Disclaimer: This is a learning project
```  
