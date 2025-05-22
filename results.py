#!/usr/bin/env python3
import json
import sys
from datetime import datetime
from opensearchpy import OpenSearch, helpers

OPENSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "cortex-analyses"

client = OpenSearch([OPENSEARCH_HOST])

def index_document(doc):
   
    doc['indexed_at'] = datetime.utcnow().isoformat()
    response = client.index(index=INDEX_NAME, body=doc)
    print(f"Documento indexado, ID: {response['_id']}")

def bulk_index_documents(docs):
    actions = [
        {
            "_index": INDEX_NAME,
            "_source": {**doc, "indexed_at": datetime.utcnow().isoformat()}
        }
        for doc in docs
    ]
    helpers.bulk(client, actions)
    print(f"Se indexaron {len(docs)} documentos.")

def main():
    try:
        with open("resultados.json", "r") as f:
            data = json.load(f)
    except Exception as e:
        print("Error al leer el archivo de resultados:", e)
        sys.exit(1)
    
    if isinstance(data, dict):
        index_document(data)
    elif isinstance(data, list):
        bulk_index_documents(data)
    else:
        print("Formato de datos no reconocido")
        sys.exit(1)

if __name__ == "__main__":
    main()
