from pathlib import Path

class Foreign:
    def read_text(self) -> str: ...
    def get(self, value: str) -> str: ...
    def set(self, value: str, item: str) -> None: ...
    def write(self, value: str) -> None: ...
    def send(self, target: str, value: str) -> None: ...

def handler(path: Path, foreign: Foreign) -> None:
    path.read_text(encoding='utf-8')
    path.write_text('active', encoding='utf-8')
    opened = path.open('r', encoding='utf-8')
    opened.read()
    handle = open('fixture.txt', 'r', encoding='utf-8')
    handle.read()
    foreign.read_text()
    foreign.get('acct:42')
    foreign.set('acct:42', 'active')
    foreign.write('active')
    foreign.send('events', 'payload')
