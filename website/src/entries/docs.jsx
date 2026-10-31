import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../styles.css'
import Docs from '../pages/Docs.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Docs />
  </StrictMode>,
)
