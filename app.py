import os
import boto3

s3 = boto3.client('s3')

def respaldar(ruta):
    s3.upload_file(ruta, os.environ['S3_BUCKET'], ruta)

if __name__ == '__main__':
    respaldar('inventario.csv')
