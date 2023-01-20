PREFIX=/usr/local/libexec/jupyterhub

sync:
	sudo $(PREFIX)/bin/python3 -m piptools sync

requirements.txt: requirements.in
	docker run --rm -v$(PWD):/io -w /io --platform linux/amd64 python:3.8 sh -c 'pip install pip-tools; pip-compile'

restart: restart-rtc restart-readonly

restart-rtc:
	sudo systemctl restart jupyterhub-collaborative

restart-readonly:
	sudo systemctl restart jupyterhub-readonly

# %.service: %.txt
# 	@echo $<
#
# %.txt:
# 	@echo txt

systemd:
	# sudo cp readonly/jupyterhub-readonly.service /etc/systemd/system/jupyterhub-readonly.service
	# sudo cp readonly/jupyterhub-collaborative.service /etc/systemd/system/jupyterhub-collaborative.service
	sudo systemctl daemon-reload
	make restart
