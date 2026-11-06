.PHONY: test demo gif video svg social check clean

test:
	python3 -m unittest discover -s tests -t . -v

demo:
	python3 -m wraith demo --color always

check:
	python3 -m compileall -q wraith tests
	python3 -m unittest discover -s tests -t .

svg:
	python3 scripts/render_demo.py

gif:
	python3 scripts/render_gif.py

video:
	python3 scripts/render_gif.py --mp4

social:
	python3 scripts/render_social.py

clean:
	rm -rf runs .wraith __pycache__ wraith/__pycache__ tests/__pycache__ docs/demo.png docs/demo.html docs/demo.gif docs/demo.mp4
