"""sumary_line

Keyword arguments:
argument -- description
Return: return_description
"""

from flask import Flask
from blueprints.home import home_bp
from blueprints.packet_sniffer import packet_sniffer_bp
from blueprints.vulnerability_scanner import vulnerability_scanner_bp
from blueprints.penetration_tester import penetration_tester_bp

def create_app():
    """sumary_line
    
    Keyword arguments:
    argument -- description
    Return: return_description
    """

    app = Flask(__name__)

    # Register blueprints
    app.register_blueprint(home_bp)
    app.register_blueprint(packet_sniffer_bp)
    app.register_blueprint(vulnerability_scanner_bp)
    app.register_blueprint(penetration_tester_bp)

    return app

if __name__ == '__main__':
    flask_app = create_app()
    flask_app.run()
