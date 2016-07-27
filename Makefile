MODULE = mkSpace
SRC = $(MODULE).py
CONFIG = $(MODULE).cfg $(MODULE).json

$(MODULE).zip:	$(SRC) $(CONFIG)
		zip $(MODULE).zip $(SRC) $(CONFIG)

commit:		$(MODULE).zip
		rm -f *~
		git add Makefile $(SRC) $(MODULE).zip $(CONFIG)
		git commit -m "latest changes"
		git push -u origin master

clean:		
		rm -f $(MODULE).zip
		rm -f *~
