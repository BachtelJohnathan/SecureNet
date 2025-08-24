"""sumary_line

Keyword arguments:
argument -- description
Return: return_description
"""

from flask import Blueprint, render_template

packet_sniffer_bp = Blueprint('Packet Sniffer', __name__)

@packet_sniffer_bp.route('/packet_sniffer')
def packet_sniffer():
    """sumary_line
    
    Keyword arguments:
    argument -- description
    Return: return_description
    """

    return render_template('packet_sniffer.html')
