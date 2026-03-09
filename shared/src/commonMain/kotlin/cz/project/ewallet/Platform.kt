package cz.project.ewallet

interface Platform {
        val name: String
}

expect fun getPlatform(): Platform

