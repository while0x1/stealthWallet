
import dash_bootstrap_components as dbc
import secrets
import time
import os
from flask import Flask, redirect, session


import dash
from dash import dcc, html, Input, Output, State, ALL


app = dash.Dash(__name__, use_pages=True, external_stylesheets=[dbc.themes.DARKLY,dbc.icons.FONT_AWESOME])
#app.permanent_session_lifetime = timedelta(hours=24)
print('Alive')
VALID_USERNAME_PASSWORD = {"while0x1":"while0x1"}

# Updating the Flask Server configuration with Secret Key to encrypt the user session cookie
#server.config.update(SECRET_KEY=secrets.token_hex(16))

links = dbc.DropdownMenu(
        [
            dbc.DropdownMenuItem(page["name"], href=page["path"])
            for page in dash.page_registry.values()
            if page["module"] != "pages.not_found_404"
        ],
        nav=True,
        label="Menu",
        style={"display": "flex", "flexWrap": "wrap",'font-size':20},)     

navbar = dbc.Navbar(
    dbc.Container(
        [
            html.A(
                # Use row and col to control vertical alignment of logo / brand
                dbc.Row(
                    [
                        dbc.Col(html.Img(src=app.get_asset_url('inf.png'), height="30px")),
                        dbc.Col(dbc.NavbarBrand("StealthWallet", className="ms-2")),
                    ],
                    align="center",
                    
                ),
                href="/",
                style={"textDecoration": "none"},
            ),
            links
        ]
    ),
    color="dodgerblue",
    dark=True,
    sticky='top',
)


nav = dbc.Nav(
    [
        #dbc.NavLink(
        #    html.Img(
        #        src=app.get_asset_url('while0x1_test.svg'),height="60px"),
        #    active=True, href="https://twitter.com/sharethlovelace"),
        dbc.NavLink(
                html.Span(
                    html.I(className="fa-brands fa-github fa-3x"),style={"color": "Dodgerblue"})
            ,active=True,href="https://www.github.com",),
        dbc.NavLink(
                html.Span(
                    html.I(className="fa-brands fa-twitter fa-3x"),style={"color": "Dodgerblue"})
            ,active=True,href="https://www.twitter.com"),
    ],
    className="fixed-bottom justify-content-center bg-dark pt-2",
)

app.layout = html.Div(children = [
    dcc.Store(id="store", storage_type='session', data={}),
    dcc.Location(id="url"),
    dcc.Location(id='redirect', refresh=True),
    navbar,
    html.Div(id="user-status-header"),
    dash.page_container,
    nav])



if __name__ == "__main__":
    app.run_server(host='0.0.0.0',debug=False)
