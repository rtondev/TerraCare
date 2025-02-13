from app import app

# Necessário para Vercel
def handler(request, context):
    return app(request, context) 