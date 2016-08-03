MODULE = mkSpace
SRC = $(MODULE).py aws.py github.py
CONFIG = $(MODULE).cfg api.json
m=latest incremental changes

$(MODULE).zip:	$(SRC) $(CONFIG)
		zip $(MODULE).zip $(SRC) $(CONFIG)

commit:		$(MODULE).zip
		rm -f *~
		git add Makefile $(SRC) $(MODULE).zip $(CONFIG)
		git commit -m "$(m)" 
		git push -u origin master

clean:		
		rm -f $(MODULE).zip
		rm -f *~ *.pyc
