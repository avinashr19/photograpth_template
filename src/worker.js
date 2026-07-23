import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()
app.use('*', cors())

// ══════════════════════════════════════════════════════════════
// JWT  (Web Crypto — zero npm deps)
// ══════════════════════════════════════════════════════════════
const b64u = {
  enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
  dec: str => Uint8Array.from(
    atob(str.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0)
  )
}

async function signJWT (payload, secret) {
  const h = b64u.enc(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
  const b = b64u.enc(new TextEncoder().encode(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 28800   // 8 hours
  })))
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${h}.${b}`))
  return `${h}.${b}.${b64u.enc(sig)}`
}

async function verifyJWT (token, secret) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Malformed token')
  const [h, b, sig] = parts
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  )
  const ok = await crypto.subtle.verify(
    'HMAC', key,
    b64u.dec(sig),
    new TextEncoder().encode(`${h}.${b}`)
  )
  if (!ok) throw new Error('Invalid signature')
  const payload = JSON.parse(new TextDecoder().decode(b64u.dec(b)))
  if (payload.exp < Date.now() / 1000) throw new Error('Token expired')
  return payload
}

// ══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ══════════════════════════════════════════════════════════════
async function requireAuth (c, next) {
  const auth = c.req.header('Authorization') ?? ''
  if (!auth.startsWith('Bearer ')) return c.json({ error: 'No token provided' }, 401)
  try {
    c.set('user', await verifyJWT(auth.slice(7), c.env.JWT_SECRET))
    await next()
  } catch {
    return c.json({ error: 'Invalid or expired token' }, 403)
  }
}

// ══════════════════════════════════════════════════════════════
// DEFAULT CONTENT  (used when KV is empty on first deploy)
// ══════════════════════════════════════════════════════════════
const DEFAULT_CONTENT = {
  site: {
    name:      'IMAGE PHOTO STUDIO',
    tagline:   'Where Every Frame Tells a Story',
    logoImage: ''
  },

  whatsapp: {
    number:  '918897111768',
    message: "Hi! I'd like to book a photography session at IMAGE PHOTO STUDIO. Please share your packages and availability."
  },

  hero: {
    heading:      "Every Moment\nTells a Story",
    subheading:   'Professional photography studio in Manikonda, Hyderabad. Specializing in weddings, pre-weddings, portraits, birthdays & custom framing.',
    image:        '',
    imageFallback:'https://images.unsplash.com/photo-1519741497674-611481863552?w=1920&q=85'
  },

  stats: [
    { value: '1200+', label: 'Sessions Shot' },
    { value: '9+ Yrs', label: 'Experience' },
    { value: '★ 4.9', label: 'Google Rating' }
  ],

  services: {
    heading: 'Our Photography Specializations',
    items: [
      { icon: '💍', title: 'Wedding Photography',    description: 'Timeless, editorial wedding coverage that captures every precious moment of your big day.', filter: 'wedding'    },
      { icon: '🌸', title: 'Pre-Wedding Shoots',     description: 'Romantic and relaxed sessions that showcase your unique love story before the wedding.',   filter: 'prewedding' },
      { icon: '🎂', title: 'Birthday & Events',      description: 'Vibrant and joyful photography for birthdays, anniversaries and special celebrations.',       filter: 'birthday'   },
      { icon: '🎭', title: 'Portrait Photography',   description: 'Striking professional portraits for individuals, families and corporate headshots.',          filter: 'portrait'   },
      { icon: '👨‍👩‍👧', title: 'Family Photography',    description: 'Warm, candid family sessions that capture the bonds and joy that matter most.',            filter: 'family'     },
      { icon: '🤰', title: 'Maternity Shoots',       description: 'Soft and beautiful maternity photography celebrating the journey into motherhood.',           filter: 'maternity'  }
    ]
  },

  testimonials: [
    {
      name:   'Fazil Kadri',
      badge:  'Local Guide · 9 reviews · 30 photos',
      rating: 5,
      text:   'Very professional, courteous and prompt in their service. Highly recommended.',
      date:   '3 months ago'
    },
    {
      name:   'Anand Kumar',
      badge:  '3 reviews',
      rating: 5,
      text:   'Excellent editing in time i prefer this studio for manikonda location',
      date:   '3 months ago'
    },
    {
      name:   'sudheer reddy',
      badge:  'Local Guide · 55 reviews · 14 photos',
      rating: 5,
      text:   'I got a frame done here. Overall nice experience and satisfied with the work',
      date:   'a year ago'
    },
    {
      name:   'Lakshminarayana Arekatla',
      badge:  'Local Guide · 8 reviews · 6 photos',
      rating: 5,
      text:   'Excellent photo studio and Mr.Raj Kumar Garu n very good person i fully satisfy for my orders and works.',
      date:   'a year ago'
    },
    {
      name:   'Sai Chandrakanth',
      badge:  '2 reviews',
      rating: 5,
      text:   'Super Photography, Best Quality, Good Service for Customer',
      date:   '10 months ago'
    },
    {
      name:   'MindtoMuscle bodybuilding',
      badge:  '4 reviews',
      rating: 5,
      text:   'Great service 🫡',
      date:   '3 months ago'
    }
  ],

  gallery: [
    { id: 1, cat: 'wedding', title: 'The Golden Hour Kiss', effect: 'Warm Tones', url: 'https://images.unsplash.com/photo-1519741497674-611481863552?w=800&q=85' },
    { id: 2, cat: 'wedding', title: 'Walking into Forever', effect: 'Film Grain', url: 'https://images.unsplash.com/photo-1583939411023-14783179e581?w=800&q=85' },
    { id: 3, cat: 'wedding', title: 'Bridal Glow', effect: 'Soft Glow', url: 'https://images.unsplash.com/photo-1520854221256-17451cc331bf?w=800&q=85' },
    { id: 4, cat: 'prewedding', title: 'Sunset Silhouette', effect: 'Golden Hour', url: 'https://images.unsplash.com/photo-1537633552985-df8429e8048b?w=800&q=85' },
    { id: 5, cat: 'birthday', title: 'First Candle', effect: 'Vivid Pop', url: 'https://images.unsplash.com/photo-1530103862676-de8c9debad1d?w=800&q=85' },
    { id: 6, cat: 'portrait', title: 'Soul in the Eyes', effect: 'Studio Light', url: 'https://images.unsplash.com/photo-1531746020798-e6953c6e8e04?w=800&q=85' },
    { id: 7, cat: 'family', title: 'Three Generations', effect: 'Warm & Cozy', url: 'https://images.unsplash.com/photo-1490718720478-364a07a997cd?w=800&q=85' },
    { id: 8, cat: 'maternity', title: 'New Life', effect: 'Soft & Dreamy', url: 'https://images.unsplash.com/photo-1544078751-58fee2d8a03b?w=800&q=85' }
  ],

  contact: {
    email:   'imagephotostudio@gmail.com',
    phone:   '+91 88971 11768',
    address: 'Manikonda, Hyderabad, Telangana'
  },

  footer: {
    text:   '© 2024 IMAGE PHOTO STUDIO. All rights reserved.',
    social: { instagram: '#', facebook: '#', youtube: '#' }
  }
}

// ══════════════════════════════════════════════════════════════
// ROUTES — AUTH
// ══════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async c => {
  const { username, password } = await c.req.json()
  const validUser = username === c.env.ADMIN_USERNAME
  const validPass = password === c.env.ADMIN_PASSWORD

  if (!validUser || !validPass) {
    // Artificial delay — brute-force protection
    await new Promise(r => setTimeout(r, 1000))
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const token = await signJWT({ username, role: 'admin' }, c.env.JWT_SECRET)
  return c.json({ token, expiresIn: '8h' })
})

// POST /api/auth/verify
app.post('/api/auth/verify', requireAuth, c =>
  c.json({ valid: true, user: c.get('user') })
)

// ══════════════════════════════════════════════════════════════
// ROUTES — CONTENT  (KV)
// ══════════════════════════════════════════════════════════════

// GET /api/content  — public (website & admin both read here)
app.get('/api/content', async c => {
  const data = await c.env.CONTENT_KV.get('site_content', { type: 'json' })
  return c.json(data ?? DEFAULT_CONTENT)
})

// PUT /api/content  — protected
app.put('/api/content', requireAuth, async c => {
  const body = await c.req.json()
  if (!body || typeof body !== 'object') return c.json({ error: 'Invalid payload' }, 400)
  await c.env.CONTENT_KV.put('site_content', JSON.stringify(body))
  return c.json({ success: true, message: 'Content updated successfully!' })
})

// ══════════════════════════════════════════════════════════════
// ROUTES — IMAGES  (R2)
// ══════════════════════════════════════════════════════════════

const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'])

// POST /api/upload  — protected
app.post('/api/upload', requireAuth, async c => {
  const form  = await c.req.formData()
  const file  = form.get('image')
  if (!file || typeof file === 'string') return c.json({ error: 'No file uploaded' }, 400)
  if (!ALLOWED_TYPES.has(file.type)) return c.json({ error: 'Only images allowed' }, 400)
  if (file.size > 10 * 1024 * 1024) return c.json({ error: 'File too large (max 10 MB)' }, 400)

  const ext      = file.name.split('.').pop().toLowerCase()
  const filename = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`

  await c.env.IMAGES_BUCKET.put(filename, file.stream(), {
    httpMetadata: { contentType: file.type }
  })

  return c.json({ url: `/uploads/${filename}`, filename })
})

// GET /api/uploads  — protected (admin media library)
app.get('/api/uploads', requireAuth, async c => {
  const list  = await c.env.IMAGES_BUCKET.list()
  const files = list.objects.map(o => ({ filename: o.key, url: `/uploads/${o.key}` }))
  return c.json(files)
})

// DELETE /api/uploads/:filename  — protected
app.delete('/api/uploads/:filename', requireAuth, async c => {
  await c.env.IMAGES_BUCKET.delete(c.req.param('filename'))
  return c.json({ success: true })
})

// ══════════════════════════════════════════════════════════════
// SERVE IMAGES FROM R2  (public)
// ══════════════════════════════════════════════════════════════
app.get('/uploads/:filename', async c => {
  const obj = await c.env.IMAGES_BUCKET.get(c.req.param('filename'))
  if (!obj) return c.notFound()

  const headers = new Headers()
  obj.writeHttpMetadata(headers)
  headers.set('etag', obj.httpEtag)
  headers.set('cache-control', 'public, max-age=31536000, immutable')

  return new Response(obj.body, { headers })
})

// ══════════════════════════════════════════════════════════════
// FALLTHROUGH → Static Assets (Pages / Workers Assets)
// ══════════════════════════════════════════════════════════════
app.all('*', c => c.env.ASSETS.fetch(c.req.raw))

export default app
