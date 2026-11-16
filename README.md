<img src="docs/banner.svg" alt="Banner do Jev IDS mostrando o logotipo jev_ids no terminal, a frase 'Detecção de intrusões com um System One Model, em um fluxo contínuo de conexões cujos rótulos chegam com atraso', e o comando que executa o CIC-IDS2017 pelo sistema completo" width="100%" />

# Jev IDS

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-0B6B3A?style=flat&labelColor=121917) ![Detector Jev, da TypeSafe](https://img.shields.io/badge/detector-Jev%20%28TypeSafe%29-0B6B3A?style=flat&labelColor=121917) ![Datasets CIC-IDS2017 e NSL-KDD](https://img.shields.io/badge/datasets-CIC--IDS2017%20%C2%B7%20NSL--KDD-0B6B3A?style=flat&labelColor=121917) ![Licença MIT](https://img.shields.io/badge/license-MIT-0B6B3A?style=flat&labelColor=121917)

**Detecção de intrusões em um fluxo contínuo de conexões de rede — estendida com um laço adversarial fechado em Agno (NSL-KDD / Unipampa) e suporte ao Gemini Decision. A cada fluxo, o Jev IDS seleciona alguns registros já rotulados e os envia em uma única requisição a um modelo de decisão ([Jev da TypeSafe](https://docs.typesafe.ai/introduction) ou Gemini Decision), respondendo se há ataque e qual a categoria, sem texto livre para parsear.**

Um sistema de detecção de intrusões (IDS) monitora o tráfego de uma rede e dispara um alerta quando suspeita de ataque. O Jev IDS faz isso mostrando ao modelo de IA **Jev** alguns fluxos cuja categoria já é conhecida e pedindo que julgue o novo registro. Dois componentes escolhem o que o Jev vê: o **KController** define quantos exemplos de cada tipo de tráfego mostrar, e o **Selector** escolhe quais deles enviar. Em uma rede real, a confirmação de que um fluxo foi ataque chega com atraso; por isso o Jev IDS foi avaliado no CIC-IDS2017, um benchmark público de ataques de rede, com essa confirmação chegando de 1 a 200 fluxos depois. Com atraso de 1 fluxo, o Jev IDS e o detector clássico mais forte testado (Random Forest) ficam empatados. A partir de um atraso de 25 fluxos, todas as três execuções do Jev IDS obtiveram F1 maior que qualquer detector clássico, e a vantagem cresce com o atraso — principalmente em ataques zero-day nunca vistos antes. Com atraso de 200 fluxos, o Jev IDS capturou 54% deles contra 29% do Random Forest.

[Ler o laço de stream](jev_ids/stream.py) · [O laço adversarial](jev_ids/adversarial.py) · [Template da requisição](prompts/cicids2017/jev.json) · [Dashboard HTML](docs/dashboard.html) · [Registro de design](docs/jevids-design.md) · [Glossário](CONTEXT.md)

## O problema

Um fluxo (*flow*) é o resumo de uma conversa entre dois computadores. Ele registra quantos pacotes e bytes trafegaram em cada direção, quanto tempo a conexão durou, qual porta foi usada e dezenas de outras medidas. No CIC-IDS2017, cada linha é um fluxo descrito por 83 colunas de atributos e por um rótulo indicando se é tráfego normal ou a qual ataque pertence.

Um IDS recebe cada fluxo e decide se é tráfego legítimo (*benigno*) ou parte de um ataque. Quando decide ataque, emite um alerta.

Dois fatores tornam a tarefa difícil. O primeiro é o surgimento de ataques que o sistema nunca viu — os **ataques zero-day** definidos abaixo. Um detector que aprendeu apenas com exemplos antigos tende a classificar um ataque zero-day como tráfego normal. O segundo é que a resposta correta chega atrasada: um analista de segurança só confirma que um fluxo foi ataque algum tempo depois, quando o impacto aparece ou alguém investiga. Até lá, o sistema continua julgando novos fluxos sem saber se acertou os anteriores.

> **Ataque zero-day.** Em segurança de redes, um ataque zero-day é um ataque que os defensores ainda não conhecem quando ocorre, tendo tido zero dias para se preparar. Aqui, os ataques zero-day são os três nomes de ataque do conjunto de teste que nunca aparecem na memória inicial do sistema ([Como foi testado](#como-foi-testado)). O sistema os encontra pela primeira vez durante o teste, sem nenhum exemplo prévio deles.

Esse atraso é chamado de **D** e é medido em quantidade de fluxos. Com D = 1, o rótulo de um fluxo volta logo antes de o próximo fluxo ser julgado. Com D = 200, só retorna depois que outros 200 fluxos já foram julgados.

## Como funciona

O Jev é um modelo de IA da TypeSafe, de um tipo chamado *System One Model*. Ele lê um `state` (bloco de informações) e responde perguntas tipadas sobre esse estado com probabilidades, sem gerar texto livre para ser interpretado. O Jev IDS coloca no `state` as instruções, os nomes das 83 colunas, uma descrição de cada categoria, alguns fluxos cuja categoria já é conhecida (os exemplos) e o fluxo sob teste. Em seguida faz duas perguntas: `is_attack` retorna uma probabilidade entre 0 e 1 chamada `p_attack`; `category` retorna uma entre seis categorias com um valor de confiança. As categorias são tráfego benigno (`BENIGN`) e cinco famílias de ataque listadas em [Como foi testado](#como-foi-testado).

<img src="docs/verdict.svg" alt="Um fluxo, duas respostas tipadas. is_attack, uma pergunta noul, retorna 0,80, acima do corte de 0,58, portanto o veredito é ataque. category, uma pergunta choice, retorna DoS com confiança 0,89. O fluxo é o primeiro de uma rajada zero-day de DoS Slowhttptest" width="100%" />

A figura mostra um fluxo real do teste — o primeiro fluxo do ataque zero-day `DoS Slowhttptest`, respondido pelo Jev com D = 200. A barra superior mostra `p_attack` = 0,80, acima do limiar de corte 0,58, gerando alerta de ataque. A barra inferior distribui a probabilidade entre as seis categorias, com 0,91 concentrados em DoS e confiança de 0,89.

Ao redor dessa requisição roda um laço sobre o fluxo contínuo de conexões. A figura abaixo ilustra o fluxo de execução e os seis passos seguintes acompanham um registro por ele.

<img src="docs/stream.svg" alt="O laço do Jev IDS. A memória guarda os fluxos do pool encerrados antes do fluxo em teste e os fluxos já julgados cujo rótulo retornou. O KController define k por categoria e o Selector escolhe os exemplos em formato compacto. Uma requisição vai para o Jev, cujo p_attack gera o veredito em 0,58, e o rótulo verdadeiro volta D fluxos depois para a memória e o KController" width="100%" />

A linha superior representa um passo: o fluxo em teste vai para o Jev em uma requisição, e a resposta gera o veredito e uma linha de resultado. A linha inferior mostra o que o Jev IDS acrescenta ao redor do Jev: a memória alimenta o KController e o Selector, que escolhem os exemplos enviados na requisição. A linha tracejada indica o rótulo verdadeiro de cada fluxo julgado, que retorna D fluxos depois para a memória e para o KController.

A memória armazena os fluxos rotulados disponíveis para seleção de exemplos: os fluxos do *pool* (preparado antes do teste) encerrados antes do fluxo atual e todos os fluxos já julgados cujo rótulo retornou.

1. **O fluxo chega.** O CIC-IDS2017 foi gravado registrando cada conexão no encerramento, então um IDS real só recebe um fluxo quando ele termina. O Jev IDS ordena os fluxos de teste pelo instante de término (início + duração) e os julga um por vez nessa ordem, usando apenas informação que já existiria naquele momento.
2. **O KController decide quantos exemplos enviar.** Ele mantém um valor `k` para cada categoria. Antes de cada julgamento, o Jev recebe `k` exemplos de cada categoria (arredondado para cima). Todos começam em `k = 1`.
3. **O Selector escolhe os exemplos.** Dentro de cada categoria na memória, prioriza os fluxos mais parecidos com o fluxo atual, os mais recentes e aqueles sobre os quais o modelo teve menor certeza. Depois aplica *Maximal Marginal Relevance (MMR)* para evitar quase-duplicatas e mostrar casos variados. Por fim, garante que o fluxo benigno mais próximo esteja incluído (*nearest benign flow*), para o Jev sempre enxergar o tráfego normal mais próximo do registro avaliado.
4. **O registro compacto encurta o texto.** Valores decimais vão ao Jev com 4 dígitos significativos (`25160.418` vira `25160`), enquanto inteiros (como portas) permanecem exatos e todas as colunas são mantidas. Isso economiza de 21% a 25% dos tokens (e do custo) sem perda de F1.
5. **O Jev responde e o Jev IDS decide.** O Jev devolve `p_attack`, e o Jev IDS emite alerta quando `p_attack >= 0,58` no benchmark CIC-IDS2017 (corte definido antes do teste no split `validation` de 300 fluxos; o padrão geral em `records.py` e no estudo NSL-KDD é `0,5`).
6. **O rótulo volta D fluxos depois.** O fluxo julgado entra na memória com sua categoria verdadeira e passa a servir de exemplo. O KController compara a categoria verdadeira com a predita: quando há erro, o `k` da categoria verdadeira dobra (até 8); quando há acerto, cai em `1/k` (até o mínimo de 1). Assim, o sistema mostra mais exemplos das categorias em que erra e economiza tokens nas que já domina.

A regra do KController espelha o algoritmo AIMD usado pelo TCP para controle de congestionamento (crescimento aditivo, redução multiplicativa invertida para priorizar cobertura após erros).

A requisição inteira fica em [`prompts/cicids2017/jev.json`](prompts/cicids2017/jev.json). O Python preenche apenas o fluxo em análise e os exemplos selecionados, gravando o SHA-256 do prompt como `prompt_hash` em cada linha de predição. Os exemplos recebem apenas a categoria geral — nomes específicos de ataques como `DoS Hulk` nunca chegam ao modelo.

<img src="docs/request.svg" alt="O fluxo em teste e os exemplos escolhidos pelo Selector entram em uma requisição ao Jev, com estado contendo instruções, colunas, categorias, exemplos e fluxo, e duas perguntas tipadas (noul e choice)" width="100%" />

## Como foi testado

### Os dados

O benchmark principal utiliza o CIC-IDS2017 re-rotulado por Liu et al. (IEEE CNS 2022), publicado pelo grupo DistriNet da KU Leuven. Trata-se de tráfego público capturado em rede de laboratório durante cinco dias úteis (3 a 7 de julho de 2017). O script [`scripts/prepare_cicids2017.py`](scripts/prepare_cicids2017.py) ordena os fluxos de cada dia cronologicamente e divide em duas metades: a primeira metade compõe o *pool* inicial (até 50.000 fluxos benignos e 10.000 por ataque, totalizando 88.066 fluxos), e a segunda metade forma a base de teste (19.368 fluxos, dos quais 2.000 formam o split `paper-v2`: 1.020 benignos e 980 ataques).

### As categorias

| Categoria  | Significado no tráfego                                                         | Nomes de ataque no teste e suas quantidades                                                 |
| ---------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| BENIGN     | Tráfego normal                                                                 | 1.020 fluxos                                                                                |
| DoS        | Negação de serviço por um único host tentando derrubar ou travar um servidor   | `DoS Slowloris` 101, `DoS Slowhttptest` 117 (zero-day), `DoS Hulk` 114, `DoS GoldenEye` 118 |
| DDoS       | Negação de serviço distribuída, partindo de várias máquinas ao mesmo tempo     | `DDoS` 87                                                                                   |
| PortScan   | Varredura de portas em uma máquina buscando serviços abertos                   | `Portscan` 106, `Infiltration - Portscan` 89 (zero-day)                                     |
| BruteForce | Tentativa e erro para adivinhar senhas                                         | `FTP-Patator` 114, `SSH-Patator` 87 (zero-day)                                              |
| Botnet     | Tráfego de máquinas infectadas obedecendo a um servidor de comando e controle  | `Botnet` 47                                                                                 |

### Os ataques zero-day

Três nomes de ataque nunca aparecem no *pool* inicial: `SSH-Patator` (BruteForce), `DoS Slowhttptest` (DoS) e `Infiltration - Portscan` (PortScan). Suas categorias gerais continuam presentes no *pool* por meio dos outros ataques conhecidos, permitindo avaliar a capacidade de generalização em 293 fluxos desconhecidos.

Cada ataque chega em uma rajada (*burst*) entre 116 e 171 fluxos. Atrasos `D = 1, 25, 50, 100` são menores que a menor rajada; já com `D = 200`, nenhum rótulo de um ataque zero-day retorna antes do fim da rajada, forçando o detector a reconhecê-lo sem nunca ter visto exemplos daquela assinatura.

### Os detectores comparados

- **Random Forest** (scikit-learn, 100 árvores): detecção supervisionada treinada sobre os exemplos rotulados disponíveis na memória.
- **kNN** (4 vizinhos): vota pela maioria dos fluxos mais próximos na memória usando a mesma distância do Selector.
- **Isolation Forest** (scikit-learn, 100 árvores): detecção de anomalias treinada apenas com o tráfego benigno disponível na memória.

Os três modelos clássicos são re-treinados a cada passo exatamente sobre a mesma memória conhecida pelo Jev IDS no instante `t`, com corte de alerta padrão `p_attack >= 0,5`.

### Quantas execuções

Como o Jev pode apresentar pequena variação entre chamadas repetidas, o sistema completo rodou três vezes por atraso `D`. Os detectores clássicos usam sementes fixas e rodaram uma vez cada.

## O que os números significam

- **Recall:** fração dos 980 ataques (conhecidos + zero-day) que gerou alerta. Quanto maior, melhor.
- **Recall zero-day:** fração dos 293 fluxos zero-day que gerou alerta. Quanto maior, melhor.
- **Falsos alarmes:** quantidade de fluxos benignos (entre 1.020) que gerou alerta indevido. Quanto menor, melhor.
- **F1:** média harmônica entre precisão e recall: `2 × acertos / (2 × acertos + falsos alarmes + ataques perdidos)`.
- **Teste pareado:** teste exato de sinais de McNemar focado apenas nos fluxos em que dois detectores discordam, com correção de Holm para múltiplas comparações (`p < 0,05` indica diferença estatisticamente significativa).

## Evidências e limites

No split `paper-v2` do CIC-IDS2017 (2.000 fluxos em ordem temporal), as execuções de 2026-11-02 em [`results/design-cicids2017/`](results/design-cicids2017) e documentadas em [`docs/jevids-design.md`](docs/jevids-design.md) mostram:

| D   | Jev IDS F1    | Random Forest F1 | kNN F1 | Isolation Forest F1 | Jev IDS recall zero-day | Random Forest recall zero-day | Falsos alarmes Jev IDS / 1.020 | Falsos alarmes RF / 1.020 |
| --- | ------------- | ---------------- | ------ | ------------------- | ----------------------- | ----------------------------- | ------------------------------ | ------------------------- |
| 1   | 0.984 ± 0.001 | 0.988            | 0.983  | 0.495               | 0.953                   | 0.945                         | 1 a 2                          | 1                         |
| 25  | 0.975 ± 0.002 | 0.961            | 0.951  | 0.494               | 0.883                   | 0.799                         | 2                              | 0                         |
| 50  | 0.969 ± 0.001 | 0.947            | 0.934  | 0.494               | 0.861                   | 0.713                         | 3 a 6                          | 0                         |
| 100 | 0.954 ± 0.004 | 0.906            | 0.898  | 0.495               | 0.721                   | 0.471                         | 2 a 4                          | 0                         |
| 200 | 0.923 ± 0.001 | 0.873            | 0.869  | 0.495               | 0.540                   | 0.294                         | 3                              | 0                         |

Com `D = 1`, Jev IDS e Random Forest empatam. À medida que `D` cresce, o Random Forest cai rapidamente em zero-day enquanto o Jev IDS sustenta generalização a partir das famílias conhecidas (`+0,050` de F1 e `54%` vs `29%` de recall zero-day em `D = 200`). O Isolation Forest ignora rótulos que chegam depois e permanece estável próximo de `0,495` F1 com 75–77 falsos alarmes.

<img src="docs/results-cicids2017.svg" alt="Gráficos de F1 e recall zero-day pelo atraso de feedback D no split paper-v2 do CIC-IDS2017" width="100%" />

### O que cada parte acrescenta

Estudo de ablação em `D = 1, 50 e 200`:

| Configuração          | O que muda                                   | F1 em D = 1 / 50 / 200 | Falsos alarmes | Tokens por fluxo      |
| --------------------- | -------------------------------------------- | ---------------------- | -------------- | --------------------- |
| Sistema completo      | nada                                         | 0.985 / 0.970 / 0.925  | 2 / 5 / 3      | 3.029 / 2.984 / 3.096 |
| Sem Selector          | exemplos sorteados aleatoriamente na memória | 0.925 / 0.935 / 0.886  | 69 / 65 / 58   | 3.510 / 3.490 / 3.692 |
| `k` fixo = 1          | sem KController, 1 exemplo por categoria     | 0.978 / 0.962 / 0.916  | 3 / 3 / 4      | 2.848 / 2.841 / 2.816 |
| `k` fixo = 4          | sem KController, 4 exemplos por categoria    | 0.990 / 0.978 / 0.928  | 6 / 6 / 8      | 6.033 / 6.021 / 5.899 |
| Registro completo     | valores exatos do CSV sem compactação        | 0.982 / 0.972 / 0.923  | 2 / 3 / 3      | 3.846 / 3.843 / 4.120 |
| Aleatório, `k = 4`    | sem Selector, sem KController                | 0.957 / 0.955 / 0.927  | 75 / 73 / 69   | 5.410 / 5.388 / 5.322 |
| Sem benigno próximo   | Selector sem âncora benigna mais próxima     | 0.979 / 0.971 / 0.929  | 27 / 29 / 22   | 3.300 / 3.339 / 3.351 |

O Selector é o componente de maior impacto para controlar falsos alarmes (caindo de 58–69 para 2–5 com o benigno mais próximo), e o registro compacto reduz 21–25% dos tokens mantendo o F1.

### Limites importantes

- Apenas o CIC-IDS2017 possui timestamps para stream; o NSL-KDD é avaliado em lote (*k-shot*) ou no laço adversarial abaixo.
- A variação entre repetições do Jev pode chegar a `0,009` em F1 para um mesmo `D`.
- O corte `0,58` foi ajustado no split `validation` do CIC-IDS2017 com margem estreita (`0,55` vs `0,58`); no estudo adversarial em NSL-KDD usa-se o limiar base `0,5`.
- Na simulação de stream, todos os rótulos retornam após `D` fluxos; em operação real, analistas confirmam apenas uma fração do tráfego.

## Por que é rápido e barato

- **Uma requisição, duas respostas:** probabilidade `noul` e categoria `choice` na mesma chamada, sem parser frágil.
- **Cobrança focada em entrada:** no Jev ($0,042 por milhão de tokens de entrada), 2.900–3.100 tokens/fluxo custam ~$121–$131 por milhão de vereditos (~0,22–0,24 s de mediana).
- **Fail open:** chamadas com erro gravam `error` na linha e são contadas como ausência de alerta sem derrubar a execução.

## Benchmark anterior: NSL-KDD

Antes do stream temporal, o Jev IDS foi avaliado no NSL-KDD em modo *k-shot* sem feedback contra Gemini 3.6 Flash, Random Forest e Isolation Forest (2.000 fluxos, 3 sementes, 2026-09-22). Em `k = 1`, o Jev foi 5,4× mais rápido que o LLM (0,31 s contra 1,65 s) e 22× mais barato ($74 contra $1.651 por milhão de fluxos), alcançando 74,7% contra 71,3% em zero-day (detalhes em [docs/results.md](docs/results.md) e [docs/protocol.md](docs/protocol.md)).

## Experimente

```bash
git clone https://github.com/jev-sec/jev-ids.git
cd jev-ids
uv sync
# O .env guarda TYPESAFE_API_KEY para o Jev. O Gemini (llm:gemini) usa a Vertex AI: precisa de `gcloud auth application-default login`
# e de GOOGLE_GENAI_USE_VERTEXAI=true, GOOGLE_CLOUD_PROJECT e GOOGLE_CLOUD_LOCATION=global no ambiente.
# DEEPSEEK_API_KEY e CHATGPT_CLIENT_ID atendem os outros LLMs.
```

### Benchmark CIC-IDS2017 (stream)

Baixe `CICIDS2017_improved.zip` da [versão re-rotulada de Liu et al.](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) em `data/raw/cicids2017/` e execute:

```bash
uv run python -m scripts.prepare_cicids2017
uv run jev-ids run --dataset data/cicids2017/dataset.json --detector jev --split smoke --delay 1 --k 1 --control aimd --selection score+nearest --seeds 0
```

### Benchmark NSL-KDD (k-shot estático)

Os splits de NSL-KDD (`smoke`, `internal`, `pilot`, `mid`, `hard`, `paper`) já estão em `data/nsl-kdd/splits/`. Para gerar também o `pool.csv` completo (necessário quando `--k > 0`), baixe o [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) em `data/raw/nsl-kdd/` e execute:

```bash
uv run python -m scripts.prepare_nsl_kdd
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split smoke --k 0,1
```

## Laço Adversarial Fechado (NSL-KDD — Unipampa)

Extensão acadêmica controlada sobre o Jev IDS para estudar adaptação mútua em rodadas fechadas (`ação → resposta do detector → observação → adaptação`) entre dois agentes construídos com **Agno** (`Agent` + `LearningMachine` sobre um `SqliteDb` por lado, um arquivo que o outro lado nunca abre) e um orquestrador determinístico sem LLM (`Orchestrator`).

- **Atacante (caixa-preta):** altera apenas uma nota de texto no campo `service` (índice `2` no NSL-KDD) dos registros de ataque. Observa somente contagens sobre os próprios registros: quantos foram respondidos (`attempts`), quantos geraram alerta (`alerts`) e quantos mudaram de lado desde a rodada anterior (`newly_alerted`, `newly_passing`). Não tem acesso a instruções do detector, probabilidades, gabarito, falsos alarmes ou métricas. Manter (`keep`) ou retirar (`remove`) a nota não custa nada; só uma redação nova gasta uma das `--max-attempts` tentativas.
- **Defensor (adaptativo):** altera apenas as instruções enviadas ao detector (`B` básica, `R` reforçada declarando que valores de registro são dados não confiáveis, ou revisões que ele mesmo escreve), observando ataques detectados/que passaram, falsos alarmes em tráfego legítimo, chamadas que falharam, notas testadas e o custo de cada versão já medida. O rótulo de uma versão é derivado do texto pelo código (`B`, `R`, `V3`, `V4`, …) e o rótulo que o modelo escrever é ignorado; `keep` significa as instruções em vigor, qualquer que seja o texto devolvido. As notas testadas chegam ao modelo do defensor sempre entre `<untrusted_note>` e `</untrusted_note>`, declaradas como texto escrito pelo adversário e nunca como instrução.
- **Detectores sob interface `DecisionDetector`:** `jev` (`jev-1.13.0`), `gemini_decision` (`gemini-decision-1` via `google-genai` `client.decisions.create`) e `llm:<provedor>`.
- **Trajetória esperada:** `N/B → N/R → S/R → S/B → N′/B`. Registros legítimos (`normal`) nunca recebem nota.

### Quem adapta a cada rodada

A regra do orquestrador ([`jev_ids/turns.py`](jev_ids/turns.py)) é relativa à rodada anterior, porque um detector real costuma deixar passar parte dos ataques e pegar outra parte, e uma regra de tudo ou nada nunca daria a vez ao atacante. Sobre os registros de ataque respondidos nas duas rodadas, `newly_alerted` conta os que passavam e agora geram alerta, `newly_passing` os que geravam alerta e agora passam, e `net = newly_alerted − newly_passing`.

| Situação                                                      | Quem recebe a vez | `why_adapted`          |
| ------------------------------------------------------------- | ----------------- | ---------------------- |
| Rodada 1: algum ataque passou                                 | defensor          | `attack_passed`        |
| Rodada 1: todos os ataques respondidos geraram alerta         | atacante          | `attack_alerted`       |
| `net > --noise-margin`                                        | atacante          | `attack_alerted`       |
| `−net > --noise-margin` e a nota é a mesma da rodada anterior | atacante          | `regime_loosened`      |
| Algum ataque passou                                           | defensor          | `attack_passed`        |
| Nenhum dos casos acima                                        | defensor          | `defense_under_review` |

Da rodada 2 em diante as linhas valem nessa ordem. Se o lado que recebeu a vez devolver a ação que já está em vigor (a mesma nota ou o mesmo texto de instruções), o outro lado é consultado uma vez; se ele também mantiver, o laço para com `stable`. O `rounds.jsonl` registra quem recebeu a vez (`turn`) e quem de fato adaptou (`who_adapts`).

Duas regras de não repetição são verificadas pelo código, não deixadas a cargo do prompt. Uma redação que estava em vigor quando o atacante recebeu a vez por `attack_alerted` não pode ser submetida de novo (a comparação ignora maiúsculas e espaçamento). O defensor não pode voltar a uma versão já medida contra a mesma nota, a menos que o último custo dela contra essa nota (`ataques perdidos/ataques + falsos alarmes/benignos`) tenha sido menor que o custo recém-medido da versão em vigor. Uma proposta recusada volta ao modelo com o motivo, ele é consultado mais uma vez, e uma segunda recusa conta como manter.

### 1. Instalar dependências e configurar o `.env`

```bash
uv sync
```

Crie `jev-ids/.env` (nunca versionado) apenas com as chaves dos modelos que for usar:

```env
TYPESAFE_API_KEY=...       # obrigatório para --detector jev
GEMINI_API_KEY=...         # obrigatório para --detector gemini_decision (e fallback para hydrogen)
ANTHROPIC_API_KEY=...      # obrigatório para --attacker/--defender claude (claude-sonnet-5-5)
HYDROGEN_API_KEY=...       # opcional se diferente de GEMINI_API_KEY, para --attacker/--defender hydrogen (gemini-4-hydrogen)
HYDROGEN_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
```

O `llm:gemini` (e o agente `gemini`) não usa `GEMINI_API_KEY`: ele chama a Vertex AI com `gcloud auth application-default login` e com `GOOGLE_GENAI_USE_VERTEXAI=true`, `GOOGLE_CLOUD_PROJECT` e `GOOGLE_CLOUD_LOCATION=global` no ambiente. O `gemini_decision` usa sempre a API Gemini com `GEMINI_API_KEY`, mesmo com `GOOGLE_GENAI_USE_VERTEXAI=true` definido. Sem nenhuma de `HYDROGEN_API_KEY`, `GEMINI_API_KEY` ou `GOOGLE_API_KEY`, o agente `hydrogen` recusa iniciar e nomeia as três variáveis.

### 2. Validar offline (sem chamadas pagas nem chaves)

```bash
uv run pytest tests/test_gemini_decision.py tests/test_adversarial.py tests/test_agents.py tests/test_agent_runtime.py tests/test_evaluator.py tests/test_turns.py -v --no-cov
uvx ruff check .
uv run pyright
```

### 3. Executar o laço adversarial e os detectores

```bash
# Exemplo com Gemini Decision como detector, Claude no ataque e Hydrogen na defesa
uv run jev-ids adversarial \
  --dataset data/nsl-kdd/dataset.json \
  --split smoke \
  --detector gemini_decision \
  --attacker claude \
  --defender hydrogen \
  --rounds 5 \
  --max-attempts 3 \
  --max-note-length 120 \
  --noise-margin 0 \
  --k 0

# Execução estática em passada única usando Gemini Decision
uv run jev-ids run \
  --dataset data/nsl-kdd/dataset.json \
  --detector gemini_decision \
  --split smoke \
  --k 0 \
  --seeds 0
```

Antes da primeira rodada, o modelo de cada agente responde a uma pergunta trivial, feita no mesmo formato estruturado das decisões; se a chamada falhar (chave inválida, modelo inexistente, pedido recusado pelo provedor), o comando termina com uma mensagem clara e nenhuma chamada ao detector é feita. `--noise-margin N` exige que `net` ultrapasse `N` registros para contar como mudança, o que absorve um detector que troca alguns vereditos entre duas chamadas idênticas. `--memory-dir <pasta>` guarda as memórias dos agentes fora da pasta da execução, para que persistam entre execuções: as redações que o atacante não pode repetir e o histórico de custos do defensor são recarregados no início. Use uma pasta de memória por configuração de estudo (mesmo dataset, split e detector), porque os custos só são comparáveis dentro dela.

Cada execução adversarial grava em `results/adv_<dataset>_<detector>_<timestamp>/` (o `:` de `llm:<provedor>` vira `-` no nome da pasta):
- `config.json`: parâmetros do experimento e provedores/modelos configurados por lado;
- `rounds.jsonl`: os números de cada rodada (`state_code`, `note`, `instruction_label`, `instructions_sha256`, `attacks_detected`, `attacks_passed`, `attack_errors`, `false_alarms`, `benign_errors`, `newly_alerted`, `newly_passing`, `f1`, `false_alarm_rate`, `turn`, `who_adapts`, `why_adapted`, `next_action`, `rationale`, `error`);
- `predictions.jsonl` e `responses.jsonl`: uma linha por chamada, gravada logo após a chamada, com `round`, `note`, `instruction_label` e `instructions_sha256` além dos campos da base (`dataset`, `split`, `detector`, `k`, `seed`);
- `instructions/<rótulo>.txt`: o texto de cada versão de instruções que esteve em vigor, cujo SHA-256 é o `instructions_sha256` das linhas;
- `memory/attacker.db` e `memory/defender.db`: a memória de cada agente, quando `--memory-dir` não é informado.

Os números por rodada estão em `rounds.jsonl`. O `jev-ids metrics` não serve para uma pasta adversarial, porque agrupa as linhas por célula e juntaria todas as rodadas em uma só.

Uma chamada do detector que falha vira uma linha com `error` e é contada à parte (`attack_errors`, `benign_errors`): não entra nos ataques que passaram, nos falsos alarmes, nas taxas, no F1 nem na regra de quem adapta. Depois de 10 falhas seguidas do detector (ou de uma rodada inteira sem resposta, em um split menor que isso), o laço para com `detector_stopped`. Se o modelo de um agente falhar, o laço para com `agent_unavailable:attacker` ou `agent_unavailable:defender` e o texto do erro em `error`. Nos dois casos as linhas já julgadas ficam gravadas e o comando termina com código de saída diferente de zero.

Abra também o guia visual interativo em [`docs/dashboard.html`](docs/dashboard.html); os números do simulador são ilustrativos, gerados por um detector simulado, e não resultados medidos.

## Comparar detectores

```bash
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector jev --k 1 --control aimd --selection score+nearest --seeds 0,1,2
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector random_forest --k all --seeds 0
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector isolation_forest --k all --seeds 0
uv run jev-ids run --dataset data/cicids2017/dataset.json --split paper-v2 --delay 200 --detector knn --neighbours 4 --k all --seeds 0
uv run jev-ids metrics --threshold 0.58 results/<jev_run> > results/jev.csv
uv run jev-ids metrics results/<rf_run> results/<if_run> results/<knn_run> > results/baselines.csv
uv run jev-ids compare --a results/<jev_run> --b results/<rf_run> --k-a 1 --k-b all --threshold-a 0.58 --subset novel  # novel = zero-day
```

## Reproduzir o artigo

Cada execução do artigo no CIC-IDS2017 é um alvo `make` sobre o split `paper-v2` (deixando marcações em `results/design-cicids2017/v2-done/`):

```bash
make v2-cut                  # sistema completo na validação + jev-ids threshold
make -k v2-d1                # D = 1 para sistema completo (seeds 0..2) e baselines
make -k v2-paper-jev         # sistema completo em D = 25, 50, 100 e 200 + ablações
make -k v2-paper-baselines   # os quatro baselines clássicos em D = 25..200
make -k v2-d500              # D = 500
```

O protocolo do NSL-KDD roda com `make paper`, conforme descrito em [`docs/protocol.md`](docs/protocol.md).

## Pequeno o bastante para ler

| Arquivo                                                                | Função                                                                                                                       |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [cli.py](jev_ids/cli.py)                                               | Subcomandos `run`, `redo-errors`, `metrics`, `compare`, `sign-test`, `threshold` e `adversarial`                             |
| [adversarial.py](jev_ids/adversarial.py)                               | Orquestrador fechado (`N/B → N/R → S/R → S/B → N′/B`): estado, registro por rodada, paradas e arquivos da execução           |
| [turns.py](jev_ids/turns.py)                                           | Regra de quem adapta a cada rodada, relativa à rodada anterior e sem LLM                                                     |
| [evaluator.py](jev_ids/evaluator.py)                                   | Injeção da nota em `service` e avaliador de uma rodada, com as chamadas que falharam contadas à parte                        |
| [agents.py](jev_ids/agents.py)                                         | Agentes (`AttackerAgent`, `DefenderAgent`): o que cada lado observa e decide, rótulos das instruções e não repetição         |
| [agent_runtime.py](jev_ids/agent_runtime.py)                           | Modelo Agno por provedor (`claude`, `hydrogen`, etc.), pergunta de verificação e memória em `SqliteDb` por lado              |
| [dataset.py](jev_ids/dataset.py)                                       | Ficha do dataset, pool, splits, amostragem `k-shot` e formato compacto                                                       |
| [stream.py](jev_ids/stream.py)                                         | Stream temporal, memória e rótulos retornando com atraso `D`                                                                 |
| [controller.py](jev_ids/controller.py)                                 | `KController`: ajusta `k` por categoria via AIMD espelhado                                                                   |
| [selector.py](jev_ids/selector.py)                                     | `Selector`: escolhe exemplos por similaridade/MMR e âncora benigna mais próxima                                              |
| [run.py](jev_ids/run.py)                                               | Laço estático/stream célula por célula e geração dos arquivos de saída                                                       |
| [records.py](jev_ids/records.py)                                       | Montagem das linhas de predição e gravação em JSONL                                                                          |
| [metrics.py](jev_ids/metrics.py)                                       | F1, recall por categoria, PR-AUC, tokens, custo por preço unitário, latência e testes pareados                               |
| [detectors/jev.py](jev_ids/detectors/jev.py)                           | Jev pela API da TypeSafe, um fluxo por requisição                                                                            |
| [detectors/gemini_decision.py](jev_ids/detectors/gemini_decision.py)   | Google Gemini Decisions API (`gemini-decision-1`) via `google-genai`                                                         |
| [detectors/random_forest.py](jev_ids/detectors/random_forest.py)       | Baseline clássico supervisionado (Random Forest)                                                                             |
| [detectors/knn.py](jev_ids/detectors/knn.py)                           | Baseline kNN na mesma métrica de distância do Selector                                                                       |
| [detectors/isolation_forest.py](jev_ids/detectors/isolation_forest.py) | Baseline não supervisionado treinado apenas com tráfego benigno                                                              |
| [detectors/llm.py](jev_ids/detectors/llm.py)                           | Baselines de LLM via Agno (`deepseek`, `openai`, `gemini`)                                                                   |
| [prompts/](prompts)                                                    | Uma pasta por dataset com `jev.json` e `llm.md`                                                                              |
| [scripts/](scripts)                                                    | Scripts `prepare_<dataset>.py` e geração de splits (`draw_split.py`)                                                         |
| [docs/dashboard.html](docs/dashboard.html)                             | Dashboard HTML interativo explicando a dinâmica `N/B → N′/B` e como executar o projeto                                       |

## Desenvolvimento

```bash
make check
```

Requer Python 3.13+. A bateria de qualidade executa `ruff` (incluindo docstrings Google, limite de complexidade ciclomática e máximo de 5 parâmetros), `complexipy`, `pyright` em modo estrito, `pytest` com cobertura, `vulture`, `pip-audit` e `jscpd`.

## Traga seus próprios fluxos

O Jev IDS é um protótipo de pesquisa independente, não um produto comercial, e pode ser conectado ao lado de um SIEM/IDS existente para julgar fluxos de forma assíncrona fora da linha crítica de pacotes:

### Seis passos

1. **Configure uma chave:** defina `TYPESAFE_API_KEY` (Jev) ou `GEMINI_API_KEY` (Gemini Decision) no `.env`.
2. **Descreva seus fluxos:** crie um card JSON como [`data/cicids2017/dataset.json`](data/cicids2017/dataset.json) listando colunas, campos simbólicos e categorias.
3. **Adapte o template:** copie [`prompts/cicids2017/jev.json`](prompts/cicids2017/jev.json) ajustando `columns` e `categories`.
4. **Semeie a memória:** um exemplo rotulado por categoria basta para iniciar com o `KController`.
5. **Chame o detector:** `JevDetector(load_prompt(path)).predict(flow, examples)` ou `GeminiDecisionDetector(...)` devolve `p_attack`, `category_pred` e `confidence`.
6. **Meça antes de confiar:** execute `jev-ids run --delay` e `jev-ids metrics` sobre seus próprios splits rotulados.

## Equipe (base original Jev IDS)

<table align="center">
  <tr>
    <td align="center" width="220">
      <a href="https://github.com/paulosevero"><img src="https://github.com/paulosevero.png?size=120" width="96" alt="Paulo Severo" /></a><br />
      <b>Paulo Severo</b><br />
      <a href="https://github.com/paulosevero"><code>@paulosevero</code></a>
    </td>
    <td align="center" width="220">
      <a href="https://github.com/sequincozes"><img src="https://github.com/sequincozes.png?size=120" width="96" alt="Silvio Quincozes" /></a><br />
      <b>Silvio Quincozes</b><br />
      <a href="https://github.com/sequincozes"><code>@sequincozes</code></a>
    </td>
    <td align="center" width="220">
      <a href="https://github.com/amandadiasdev"><img src="https://github.com/amandadiasdev.png?size=120" width="96" alt="Amanda Dias" /></a><br />
      <b>Amanda Dias</b><br />
      <a href="https://github.com/amandadiasdev"><code>@amandadiasdev</code></a>
    </td>
  </tr>
</table>

---

[Documentação TypeSafe](https://docs.typesafe.ai/introduction) · [Modelos e preços Jev](https://docs.typesafe.ai/models) · [CIC-IDS2017 re-rotulado](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) · [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) · [Glossário](CONTEXT.md)
