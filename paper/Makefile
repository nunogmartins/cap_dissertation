all: paper

paper:
	pdflatex dynamic_filter
	bibtex dynamic_filter
	pdflatex dynamic_filter
	pdflatex dynamic_filter

clean:
	rm dynamic_filter.aux 
	rm dynamic_filter.blg
	rm dynamic_filter.pdf
	rm dynamic_filter.bbl
	rm dynamic_filter.log
