from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from mongo_connector.constants import DEFAULT_COMMIT_INTERVAL, DEFAULT_MAX_BULK
from mongo_connector.doc_managers import elastic_doc_manager


class DocManager(elastic_doc_manager.DocManager):
    """Amazon AWS Elasticsearch implementation of the DocManager interface.
    """
    def __init__(self, url, auto_commit_interval=DEFAULT_COMMIT_INTERVAL,
                 unique_key='_id', chunk_size=DEFAULT_MAX_BULK,
                 meta_index_name="mongodb_meta", meta_type="mongodb_meta",
                 attachment_field="content", **kwargs):
        super(DocManager, self).__init__(url, auto_commit_interval, unique_key, chunk_size, meta_index_name, meta_type, attachment_field, **kwargs)

    def _create_elasticsearch_client(self, url, **kwargs):
        options = kwargs.get('clientOptions', {})
        client_options = options.copy()
        aws_options = client_options.pop('aws', None)
        if aws_options is None:
            elastic = Elasticsearch(hosts=[url], **client_options)
            return elastic

        aws_auth = self.create_aws_auth(aws_options)
        client_options["http_auth"] = aws_auth
        client_options["connection_class"] = RequestsHttpConnection
        elastic = Elasticsearch(
            hosts=[url],
            **client_options)
        return elastic

    @staticmethod
    def create_aws_auth(aws_options):
        aws_auth = AWS4Auth(
            aws_options.get('accessKeyId'),
            aws_options.get('secretAccessKey'),
            aws_options.get('region'),
            'es')
        return aws_auth