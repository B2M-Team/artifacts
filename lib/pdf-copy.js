// What the pdf viewer page says when the browser will not render the PDF inline: a browser that
// refuses application/pdf shows the <object>'s fallback, and the shell's probe swaps it in when a
// browser accepts the type and then paints nothing. With downloads off there is nothing to offer,
// and saying so beats a page that looks broken. A viewer reads "PDF" or "page", never "artifact".
export const PDF_FALLBACK_TEXT = {
  download: 'This browser will not show a PDF on the page. Open it in a new tab or save it instead.',
  noDownload: 'This browser will not show a PDF on the page, and downloads are off for this PDF.',
};
