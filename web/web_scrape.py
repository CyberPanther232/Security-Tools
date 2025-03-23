#!/usr/bin/python3

"""
Program: web_scrape.py
Purpose: Generic Web Scraping Python script template to help users gather data from html code on website
Developer: Cybersniper-dev
"""

import lxml.html
import requests

# Example Data
form_data = {"username": "testuser", "Submit": "Submit"}

def main():
	# This is not an actual website - You have to enter your own website
	page = requests.post("""http://testsite/test.php?'""", data=form_data)
	tree = lxml.html.fromstring(page.content)

	authors = tree.xpath('//*/table/tr/*//text()') # One '/' equals the first line of text and '//' gives you all of them
	quotes = tree.xpath('//span[@class="text"]/text()')
	tags = tree.xpath('//div[@class="tags"]/a[@class="tag"]/text()')

	print ('Authors: ', authors)
	print ('\n\nQuotes: ', quotes)
	print ('\n\nTags: ', tags)

if __name__ == "__main__":
	main()

