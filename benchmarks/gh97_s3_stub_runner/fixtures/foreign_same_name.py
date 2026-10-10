class Foreign:
    def put_object(self, *args: object, **kwargs: object) -> None: ...


def run(client: Foreign) -> None:
    client.put_object(Bucket="b", Key="k", Body=b"payload")
