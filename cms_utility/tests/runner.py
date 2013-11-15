from os import path
import sys
import nose


def insert_python_path():
    project_path = path.dirname(
        path.dirname(
            path.dirname(
                path.abspath(__file__)
            )
        )
    )
    print project_path
    sys.path.insert(0, project_path)


if __name__ == '__main__':
    insert_python_path()
    argv = ['-v']
    argv.extend(sys.argv[1:])
    nose.run(argv=argv)
