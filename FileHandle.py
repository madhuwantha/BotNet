class Filehandle(object):
    def __init__(self, path: str, action='w'):
        self._path = path
        self._action = action
        self._file = self._getFile()

    def write(self, text: str):
        self._file.write(text)

    def close(self):
        self._file.close()

    def _getFile(self):
        try:
            return open(self._path, self._action)
        except:
            print("Something went wrong in opening file")
        finally:
            print("The 'try except' is finished")
            # TODO :
