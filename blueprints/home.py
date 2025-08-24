"""sumary_line

Keyword arguments:
argument -- description
Return: return_description
"""

from flask import Blueprint, render_template

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def index():
    """sumary_line
    
    Keyword arguments:
    argument -- description
    Return: return_description
    """

    return render_template('index.html')
