from mypy_boto3_s3.client import S3Client


def run(client: S3Client) -> None:
    client.put_object(Bucket=1, Key="k", Body=b"payload")
