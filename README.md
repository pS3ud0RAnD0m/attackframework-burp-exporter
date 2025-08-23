# Attack Framework: Burp Exporter

> ⚠️ **Development Status**: This extension is in early development. While the UI is functional and loads successfully in Burp Suite, core data extraction and sink integration (e.g., OpenSearch) are still being implemented. Expect breaking changes and partial functionality.

This Burp Suite extension continuously exports traffic, issues, and other project data into structured formats optimized for ingestion by data lakes and vector databases, such as OpenSearch, Qdrant, and Weaviate.

By externalizing Burp’s insights into searchable, semantically indexed stores, this extension enables advanced querying, cross-project correlation, and integration with agentic pentesting workflows. This allows autonomous or assisted systems to reason over historical findings, surface patterns, and drive automated reconnaissance and exploitation logic.

**Attack Framework: Burp Exporter** is part of the larger [Attack Framework](https://github.com/attackframework/attackframework) open-source initiative — a modular ecosystem for integrating offensive security tools with modern AI and data infrastructure.

We welcome ideas, feedback, and pull requests. Feel free to open a discussion, issue, or submit a PR.

## License

This project is licensed under the [MIT License](LICENSE).