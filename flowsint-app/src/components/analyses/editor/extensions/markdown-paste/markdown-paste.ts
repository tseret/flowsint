import { Extension } from '@tiptap/core'
import { Plugin } from '@tiptap/pm/state'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

function looksLikeMarkdown(text: string): boolean {
  return (
    /^#{1,6}\s/m.test(text) ||
    /\*\*[^*]+\*\*/.test(text) ||
    /\[.+\]\(.+\)/.test(text) ||
    /^[-*+]\s/m.test(text) ||
    /^\d+\.\s/m.test(text) ||
    /^>\s/m.test(text) ||
    /^```/m.test(text) ||
    /^---$/m.test(text) ||
    /!\[.*\]\(.*\)/.test(text) ||
    /^- \[[ x]\]/m.test(text)
  )
}

export const PasteMarkdown = Extension.create({
  name: 'pasteMarkdown',

  addProseMirrorPlugins() {
    const { editor } = this

    return [
      new Plugin({
        props: {
          handlePaste(_view, event) {
            const text = event.clipboardData?.getData('text/plain')
            if (!text) return false

            if (looksLikeMarkdown(text)) {
              try {
                const html = DOMPurify.sanitize(marked.parse(text, { async: false }))
                editor.chain().focus().insertContent(html).run()
                return true
              } catch (e) {
                console.error('[PasteMarkdown]', e)
                return false
              }
            }
            return false
          }
        }
      })
    ]
  }
})
