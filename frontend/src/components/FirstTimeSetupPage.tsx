import { useEffect, useState } from 'react'
import { Loader2, Network, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { CompleteSetupPayload, SetupStatusResponse } from '@/api/client'
import { setupApi } from '@/api/client'
import { toast } from 'sonner'

export function FirstTimeSetupPage({ onComplete }: { onComplete: () => void }) {
  const [hints, setHints] = useState<SetupStatusResponse | null>(null)
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [publicUrl, setPublicUrl] = useState('')
  const [setupSecret, setSetupSecret] = useState('')
  const [loadingHints, setLoadingHints] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    setupApi
      .status()
      .then((r) => {
        setHints(r.data)
        setIssuer(r.data.issuer_url_hint)
        setClientId(r.data.client_id_hint)
        setRedirectUri(r.data.redirect_uri_hint)
        setPublicUrl(r.data.public_app_hint)
      })
      .catch(() => {
        toast.error('Could not load setup status — check connectivity')
      })
      .finally(() => setLoadingHints(false))
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    const payload: CompleteSetupPayload = {
      authentik_issuer_url: issuer.trim(),
      authentik_client_id: clientId.trim(),
      authentik_client_secret: clientSecret.trim(),
      authentik_redirect_uri: redirectUri.trim(),
      public_app_url: publicUrl.trim(),
    }
    try {
      await setupApi.complete(payload, hints?.requires_setup_secret ? setupSecret : undefined)
      toast.success('Authentik is configured — you can sign in with SSO.')
      onComplete()
    } catch (err: unknown) {
      const detail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string | unknown } } }).response?.data?.detail
          : undefined
      const msg =
        typeof detail === 'string'
          ? detail
          : 'Setup failed — check issuer URL and Authentik client settings.'
      toast.error(msg)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex h-screen w-screen items-start justify-center overflow-y-auto bg-[#0d1117] py-10 px-4">
      <div
        className="fixed inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(#00d4ff 1px, transparent 1px), linear-gradient(90deg, #00d4ff 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      <div className="relative w-full max-w-lg">
        <div className="flex flex-col items-center gap-3 mb-6">
          <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/20">
            <ShieldCheck size={28} className="text-[#00d4ff]" />
          </div>
          <div className="text-center space-y-1">
            <h1 className="text-xl font-semibold text-foreground tracking-wide inline-flex items-center gap-2">
              <Network size={20} className="text-[#00d4ff]" />
              First-time setup
            </h1>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Configure Authentik OpenID Connect. This page is only shown until setup completes — then SSO lives under
              Sidebar → Settings → Authentik.
            </p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="flex flex-col gap-3.5 bg-[#161b22] border border-[#30363d] rounded-xl p-6 relative"
        >
          {loadingHints && (
            <div className="absolute inset-0 flex items-center justify-center bg-[#161b22]/70 rounded-xl z-10">
              <Loader2 className="animate-spin text-[#00d4ff]" size={24} />
            </div>
          )}

          <div className="flex flex-col gap-1">
            <Label htmlFor="issuer" className="text-xs text-muted-foreground">
              Issuer URL
            </Label>
            <Input
              id="issuer"
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
              placeholder="https://auth.example.com/application/o/homelable/"
              className="bg-[#21262d] border-[#30363d] text-sm font-mono"
              required
            />
            <p className="text-[10px] text-muted-foreground">From Authentik → Providers → OpenID issuer (ends with /)</p>
          </div>

          <div className="flex flex-col gap-1">
            <Label htmlFor="cid" className="text-xs text-muted-foreground">
              Client ID
            </Label>
            <Input
              id="cid"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-[#21262d] border-[#30363d] text-sm font-mono"
              required
            />
          </div>

          <div className="flex flex-col gap-1">
            <Label htmlFor="csec" className="text-xs text-muted-foreground">
              Client secret
            </Label>
            <Input
              id="csec"
              type="password"
              autoComplete="off"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              className="bg-[#21262d] border-[#30363d] text-sm font-mono"
              required
            />
          </div>

          <div className="flex flex-col gap-1">
            <Label htmlFor="redir" className="text-xs text-muted-foreground">
              Redirect URI (must match Authentik)
            </Label>
            <Input
              id="redir"
              value={redirectUri}
              onChange={(e) => setRedirectUri(e.target.value)}
              placeholder={hints?.redirect_uri_hint || ''}
              className="bg-[#21262d] border-[#30363d] text-sm font-mono"
              required
            />
            <p className="text-[10px] text-muted-foreground leading-tight">
              Same path backend uses:{' '}
              <code className="text-[#79c0ff]">…/api/v1/auth/oidc/callback</code>
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <Label htmlFor="pub" className="text-xs text-muted-foreground">
              Public site URL (Homelable in the browser)
            </Label>
            <Input
              id="pub"
              value={publicUrl}
              onChange={(e) => setPublicUrl(e.target.value)}
              placeholder={hints?.public_app_hint || 'https://homelable.example.com'}
              className="bg-[#21262d] border-[#30363d] text-sm font-mono"
              required
            />
          </div>

          {hints?.requires_setup_secret && (
            <div className="flex flex-col gap-1 pt-1 border-t border-[#30363d] mt-1">
              <Label htmlFor="ssec" className="text-xs text-muted-foreground">
                Setup secret
              </Label>
              <Input
                id="ssec"
                type="password"
                autoComplete="off"
                value={setupSecret}
                onChange={(e) => setSetupSecret(e.target.value)}
                className="bg-[#21262d] border-[#30363d] text-sm"
                required={hints.requires_setup_secret}
              />
              <p className="text-[10px] text-muted-foreground">
                Set <span className="font-mono">HOMELABABLE_SETUP_SECRET</span> in the backend environment.
              </p>
            </div>
          )}

          <Button
            type="submit"
            disabled={submitting || loadingHints}
            className="mt-2 bg-[#00d4ff] text-[#0d1117] hover:bg-[#00d4ff]/90 font-medium"
          >
            {submitting ? <Loader2 size={15} className="animate-spin" /> : 'Save and finish setup'}
          </Button>
        </form>
      </div>
    </div>
  )
}
