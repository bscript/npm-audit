import React, { useState, useEffect } from 'react'

interface ToastProps {
    message: string
    duration?: number
    onClose?: () => void
    backgroundColor?: string
    textColor?: string
  }
  
  export const Toast: React.FC<ToastProps> = ({ message, duration = 3000, onClose, backgroundColor = 'bg-white', textColor = 'text-gray-800' }) => {
    const [isVisible, setIsVisible] = useState(true)
  
    useEffect(() => {
      const timer = setTimeout(() => {
        setIsVisible(false)
        onClose && onClose()
      }, duration)
  
      return () => clearTimeout(timer)
    }, [duration, onClose])
  
    if (!isVisible) return null
  
    return (
      <div className={`fixed bottom-4 right-4 ${backgroundColor} ${textColor} px-4 py-2 rounded-md shadow-lg animate-fade-in`}>
        {message}
      </div>
    )
  }