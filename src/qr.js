import qrcode from 'qrcode-generator'

/**
 * One QR code as a standalone SVG. Error correction M keeps the code readable
 * from a phone at a modest size without inflating the module count.
 * @param {string} text
 * @param {{ cellSize?: number, margin?: number }} [options]
 * @returns {string}
 */
export function qrSvg(text, { cellSize = 4, margin = 8 } = {}) {
  const code = qrcode(0, 'M')
  code.addData(text)
  code.make()
  return code.createSvgTag({ cellSize, margin, scalable: true })
}
