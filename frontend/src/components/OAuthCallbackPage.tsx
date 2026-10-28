import { useEffect, useState } from 'react'
import { Loader2, Network } from 'lucide-react'
import { toast } from 'sonner'

import { useAuthStore } from '@/stores/authStore'

/**
 * Parses #access_token=… or #error=… after Authentik redirects through the backend.
 */
export function OAuthCallbackPage() {
  const login = useAuthStore((s) => s.login)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : ''
    const params = new URLSearchParams(hash)
    const err = params.get('error')
    const token = params.get('access_token')
    if (err) {
      const text = decodeURIComponent(err.replace(/\+/g, ' '))
      toast.error(text || 'OAuth error')
      setDone(true)
      return
    }
    if (!token) {
      toast.error('Missing access token — try signing in again')
      setDone(true)
      return
    }
    login(token)
    window.history.replaceState(null, '', `${window.location.origin}/`)
    setDone(true)
  }, [login])

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-[#0d1117]">
      <div className="flex flex-col items-center gap-3 text-muted-foreground text-sm">
        <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/20">
          <Network size={28} className="text-[#00d4ff]" />
        </div>
        {!done ? (
          <>
            <Loader2 size={22} className="animate-spin text-[#00d4ff]" />
            <span>Signing you in…</span>
          </>
        ) : (
          <span className="text-xs">Continue in the Homelable app.</span>
        )}
      </div>
    </div>
  )
}
