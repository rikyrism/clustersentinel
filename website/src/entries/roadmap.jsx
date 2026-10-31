import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../styles.css'
import Roadmap from '../pages/Roadmap.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Roadmap />
  </StrictMode>,
)
