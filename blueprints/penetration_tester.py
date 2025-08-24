"""sumary_line

Keyword arguments:
argument -- description
Return: return_description
"""

from flask import Blueprint, render_template

penetration_tester_bp = Blueprint('Penetration Tester', __name__)

@penetration_tester_bp.route('/penetration_tester')
def penetration_tester():
    """sumary_line
    
    Keyword arguments:
    argument -- description
    Return: return_description
    """

    return render_template('penetration_tester.html')
