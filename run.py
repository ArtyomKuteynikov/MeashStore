from app import db, create_app

# db.create_all()
application = create_app()
with application.app_context():
    db.create_all()

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5123)
