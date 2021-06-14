# Standard Python library
import os
import re
import json
import time
from datetime import datetime
from os.path import join, splitext, basename, isfile, exists, dirname, isdir

# Third-party library
import shutil
import ipywidgets as widgets
from zipfile import ZipFile, ZIP_DEFLATED
from IPython.display import display, HTML, clear_output

from impact_report_for_test import *
from base_config import *


button_207 = widgets.Button(
    description="Run Impact Report!",
    button_style='primary',
    layout=widgets.Layout(
        width='25%'
    )
)

dir_picker_207 = "/AF-2779_RDP/"

time_from_207 = widgets.DatePicker(
    placeholder='Type something',
    description='Start Date:',
    disabled=False
)

time_to_207 = widgets.DatePicker(
    placeholder='Type something',
    description='End Date:',
    disabled=False
)

output_207 = widgets.Output()
    
@output_207.capture()
def run_impact_report(b):

    clear_output()

    folder = join(CWD, dir_picker_207.value)
    end_date = time_to_207.value.strftime('%Y-%m-%d 23:59:59')
    start_date = time_from_207.value.strftime('%Y-%m-%d 00:00:00')
    
    new_report = ImpactReport(CWD)
    new_report.main(
        folder=folder,
        start_date=start_date,
        end_date=end_date
    )
    
display(dir_picker_207, time_from_207, time_to_207, button_207, output_207)
button_207.on_click(run_impact_report)
