# VRAI Systems Backend

This project is the backend infrastructure for **VRAI Systems**, a production-ready AI-powered voice receptionist platform designed for healthcare businesses. The system handles real-time voice conversations, SMS interactions, appointment management, and customer relationship management, successfully serving med spas and chiropractic clinics with 99.9% uptime.

## Case Study

For a detailed breakdown of the project's architecture, challenges, and impact, check out the [full case study](https://deltarsystems.com/about/casestudies/vraisystems).

<img width="1400" alt="VRAI Systems Dashboard" src="vrai-systems-screenshot.png">

## Overview

The backend orchestrates complex AI-driven interactions through multiple integrated services, managing everything from real-time voice conversations to appointment scheduling, payment processing, and customer data management. Built with Python Flask, it leverages concurrent processing, WebSocket connections, and advanced state management to deliver seamless customer experiences.

## Key Features

- **Real-Time Voice AI**: Integrated OpenAI Realtime API with Telnyx telephony via WebSockets, enabling natural voice conversations with sub-second latency
- **Stateful Conversation Management**: Sophisticated state machines handling multi-step appointment booking flows with 15+ validation checkpoints
- **Dual Communication Channels**: Concurrent HTTP and WebSocket servers using multiprocessing, supporting both voice calls and SMS interactions
- **AI-Powered Knowledge Base**: Semantic search using OpenAI embeddings, allowing the AI to answer questions about services, hours, and policies
- **Appointment Management**: Full integration with Google Calendar for real-time availability checking and automated event creation
- **Payment Processing**: Stripe integration for handling show-up deposits and refund management
- **Customer Relationship Management**: SQLite database with 15+ normalized tables tracking customers, appointments, messages, and interactions
- **Real-Time Dashboard Updates**: Server-Sent Events (SSE) providing sub-second latency for dashboard updates without polling
- **Automated Notifications**: Scheduled SMS reminders and follow-up messages using APScheduler
- **Security**: JWT-based authentication with environment variable configuration for all sensitive credentials

## Architecture Highlights

- **Concurrent Processing**: Multiprocessing architecture running HTTP server and WebSocket server simultaneously
- **Modular Service Design**: Separated concerns across services (AI, appointments, payments, knowledge base, SMS)
- **Persistent Storage**: Railway persistent volumes for database and file storage
- **API-First Design**: RESTful API endpoints with comprehensive error handling and validation
- **Production Deployment**: Docker containerization on Railway with health checks and automatic restarts

## Tech Stack

**Backend Framework**: Python Flask  
**Real-Time Communication**: WebSockets (OpenAI Realtime API, Telnyx Telephony)  
**Database**: SQLite with SQLAlchemy ORM  
**AI Integration**: OpenAI GPT-4, Embeddings API  
**Payments**: Stripe API  
**Calendar Sync**: Google Calendar API  
**Authentication**: JWT (PyJWT)  
**Task Scheduling**: APScheduler  
**Deployment**: Railway, Docker
