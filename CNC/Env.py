import json


class Env(object):
    env = None

    def get(self, key: str) -> str:
        if self.env is None:
            self._readEnv()
        return self.env[key]

    def _readEnv(self):
        with open("env.json") as json_data_file:
            self.env = json.load(json_data_file)
