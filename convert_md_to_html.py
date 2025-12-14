#!/usr/bin/env python3
"""Convert Markdown files to HTML with styling"""

import re
import os
import sys

def escape_html(text):
    """Escape HTML special characters"""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))

def convert_markdown_to_html(md_content):
    """Convert markdown content to HTML"""
    lines = md_content.split('\n')
    html_lines = []
    in_code_block = False
    code_block_content = []
    code_lang = ''
    in_list = False
    list_items = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Code blocks
        if line.startswith('```'):
            if not in_code_block:
                in_code_block = True
                code_lang = line[3:].strip()
                code_block_content = []
            else:
                in_code_block = False
                code_html = escape_html('\n'.join(code_block_content))
                html_lines.append(f'<pre><code class="language-{code_lang}">{code_html}</code></pre>')
                code_block_content = []
            i += 1
            continue

        if in_code_block:
            code_block_content.append(line)
            i += 1
            continue

        # Headers
        if line.startswith('# '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append(f'<h1>{convert_inline(line[2:])}</h1>')
        elif line.startswith('## '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append(f'<h2>{convert_inline(line[3:])}</h2>')
        elif line.startswith('### '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append(f'<h3>{convert_inline(line[4:])}</h3>')
        elif line.startswith('#### '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append(f'<h4>{convert_inline(line[5:])}</h4>')

        # Lists
        elif line.startswith('- ') or line.startswith('* '):
            if not in_list:
                html_lines.append('<ul>')
                in_list = True
            html_lines.append(f'<li>{convert_inline(line[2:])}</li>')

        elif re.match(r'^\d+\.\s', line):
            if not in_list:
                html_lines.append('<ol>')
                in_list = True
            content = re.sub(r'^\d+\.\s', '', line)
            html_lines.append(f'<li>{convert_inline(content)}</li>')

        # Horizontal rule
        elif line.strip() == '---':
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append('<hr>')

        # Empty line
        elif line.strip() == '':
            if in_list:
                html_lines.append('</ul>')
                in_list = False

        # Regular paragraph
        else:
            if in_list and not line.startswith('  '):
                html_lines.append('</ul>')
                in_list = False
            if line.strip():
                html_lines.append(f'<p>{convert_inline(line)}</p>')

        i += 1

    # Close any open list
    if in_list:
        html_lines.append('</ul>')

    return '\n'.join(html_lines)

def convert_inline(text):
    """Convert inline markdown to HTML"""
    # Links [text](url)
    text = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', r'<a href="\2">\1</a>', text)

    # Bold **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong>\1</strong>', text)

    # Italic *text* or _text_
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<em>\1</em>', text)
    text = re.sub(r'(?<!_)_(?!_)(.+?)(?<!_)_(?!_)', r'<em>\1</em>', text)

    # Inline code `code`
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)

    return text

def create_html_document(content, title="OmniComply Documentation"):
    """Wrap content in full HTML document"""
    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 8px;
        }}
        h3 {{
            color: #546e7a;
            margin-top: 25px;
        }}
        h4 {{
            color: #607d8b;
            margin-top: 20px;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Courier New', monospace;
            font-size: 0.9em;
            color: #c7254e;
        }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #3498db;
        }}
        pre code {{
            background: none;
            color: inherit;
            padding: 0;
        }}
        ul, ol {{
            padding-left: 30px;
            margin: 15px 0;
        }}
        li {{
            margin: 8px 0;
        }}
        a {{
            color: #3498db;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        p {{
            margin: 15px 0;
        }}
        hr {{
            border: none;
            border-top: 2px solid #ecf0f1;
            margin: 30px 0;
        }}
        strong {{
            color: #2c3e50;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <div class="container">
{content}
    </div>
</body>
</html>"""
    return template

def convert_file(input_path, output_path):
    """Convert a markdown file to HTML"""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            md_content = f.read()

        html_content = convert_markdown_to_html(md_content)
        full_html = create_html_document(html_content)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_html)

        print(f"✓ Converted: {input_path} → {output_path}")
        return True
    except Exception as e:
        print(f"✗ Error converting {input_path}: {e}")
        return False

def main():
    """Main conversion function"""
    # List of files to convert
    files_to_convert = [
        ('README.md', 'README.html'),
        ('OmniComply/README.md', 'OmniComply/README.html'),
        ('OmniComply/docs/INSTALLATION.md', 'OmniComply/docs/INSTALLATION.html'),
        ('OmniComply/docs/CONTROLS.md', 'OmniComply/docs/CONTROLS.html'),
        ('OmniComply/docs/COMPLIANCE-FRAMEWORK-MAPPINGS.md', 'OmniComply/docs/COMPLIANCE-FRAMEWORK-MAPPINGS.html'),
    ]

    converted = 0
    skipped = 0

    for input_file, output_file in files_to_convert:
        if os.path.exists(input_file):
            if convert_file(input_file, output_file):
                converted += 1
        else:
            print(f"⊘ Skipped: {input_file} (not found)")
            skipped += 1

    print(f"\n{'='*50}")
    print(f"Conversion complete!")
    print(f"Converted: {converted} files")
    if skipped > 0:
        print(f"Skipped: {skipped} files")
    print(f"{'='*50}")

if __name__ == '__main__':
    main()
